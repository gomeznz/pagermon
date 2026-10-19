"""Find locations in page text and look them up on a map.

A page gets one of three kinds of result:
  point    — coordinates in the text, or an address whose house / RAPID / property
             number the geocoder matched: shown as a pin
  area     — a street with no number (or a number the geocoder couldn't find):
             shown as a circle covering the street
  locality — only a suburb, town or place name: shown as a larger circle

Lookups use a Nominatim-compatible geocoder (OpenStreetMap by default, which in
New Zealand includes LINZ addresses with rural RAPID numbers). Results are cached
in the database and requests are limited to one a second, as the public
Nominatim usage policy requires.
"""

from __future__ import annotations

import json
import logging
import math
import queue
import re
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

from . import __version__

log = logging.getLogger("pager.locations")

DEFAULTS = {
    "loc_enabled": "0",
    "loc_geocoder": "https://nominatim.openstreetmap.org/search",
    "loc_countries": "nz",
    "loc_region": "",
    "loc_markers": "LOC:, LOCATION:, ADDR:, ADDRESS:, @",
    "loc_email": "",
    "map_tiles": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    "map_attribution": "© OpenStreetMap contributors",
}

STREET_TYPES = {
    "street": "Street", "st": "Street", "road": "Road", "rd": "Road", "avenue": "Avenue",
    "ave": "Avenue", "av": "Avenue", "drive": "Drive", "dr": "Drive", "lane": "Lane", "ln": "Lane",
    "crescent": "Crescent", "cres": "Crescent", "cr": "Crescent", "place": "Place", "pl": "Place",
    "terrace": "Terrace", "tce": "Terrace", "highway": "Highway", "hwy": "Highway", "way": "Way",
    "court": "Court", "ct": "Court", "grove": "Grove", "gr": "Grove", "parade": "Parade",
    "pde": "Parade", "esplanade": "Esplanade", "esp": "Esplanade", "quay": "Quay",
    "close": "Close", "cl": "Close", "rise": "Rise", "square": "Square", "sq": "Square",
    "boulevard": "Boulevard", "blvd": "Boulevard", "heights": "Heights", "hts": "Heights",
    "view": "View", "track": "Track", "mews": "Mews", "loop": "Loop", "circle": "Circle",
    "row": "Row", "green": "Green", "glen": "Glen", "walk": "Walk", "line": "Line",
}

# Words that often come before an address in dispatch text but are never part of
# a street name. Removed from the front of a street name candidate.
LEAD_STOPWORDS = {
    "FIRE", "HOUSE", "STRUC", "STRUCTURE", "ALARM", "ALARMS", "CAR", "VEHICLE", "VEH", "MVA", "MVC",
    "MEDICAL", "MED", "RESCUE", "SMOKE", "SCRUB", "VEGETATION", "VEG", "RUBBISH", "CHIMNEY",
    "PRIVATE", "COMMERCIAL", "RESPOND", "RESPONSE", "AT", "IN", "ON", "OF", "TO", "THE", "A",
    "NEAR", "CNR", "CORNER", "OUTSIDE", "BEHIND", "OPP", "OPPOSITE", "VIA", "AND", "INCIDENT",
    "TEST", "PAGE", "CALL", "JOB", "PRIORITY", "PRI", "URGENT", "NON", "FLAT", "UNIT", "APT",
}
# Words that end the locality after the street.
TAIL_STOPWORDS = {
    "XST", "XSTR", "XS", "X", "CROSS", "MAP", "GRID", "REF", "NEAR", "CNR", "BTWN", "BETWEEN",
    "RESPOND", "RESPONSE", "CALLER", "CALL", "PH", "PHONE", "TEL", "NOTES", "NOTE", "UNIT",
    "UNITS", "PRIORITY", "PRI", "INCIDENT", "INC", "JOB", "EVENT", "FIRE", "CAR", "AND",
    "ALARM", "SMOKE", "MEDICAL", "PATIENT", "PT", "OFF", "BY", "FROM", "TO", "FOR",
}

_WORD = r"[A-Za-z][A-Za-z'’\-]*"
_TYPES = "|".join(sorted(STREET_TYPES, key=len, reverse=True))
ADDRESS_RE = re.compile(
    r"(?:(?:\bRAPID|\bRAP|\bR/)\s*(?:NO\.?\s*|#\s*)?(?P<rapid>\d{1,6})\s*,?\s+"
    r"|(?<![\w/.])(?P<num>\d{1,5}[A-Za-z]?(?:\s*[/\-]\s*\d{1,5}[A-Za-z]?)?)\s*,?\s+)?"
    rf"(?P<name>(?:{_WORD}\s+){{0,3}}?{_WORD})"
    rf"\s+(?P<type>{_TYPES})\b\.?"
    rf"(?P<rest>(?:\s*,\s*|\s+){_WORD}(?:\s+{_WORD}){{0,2}})?",
    re.IGNORECASE,
)
STATE_HWY_RE = re.compile(
    r"(?:(?:\bRAPID|\bR/)\s*(?P<rapid>\d{1,6})\s*,?\s+|(?<![\w/.])(?P<num>\d{1,5})\s*,?\s+)?"
    r"\b(?:SH|STATE\s+HIGHWAY|STATE\s+HWY)\s*(?P<sh>\d{1,3})\b"
    rf"(?P<rest>(?:\s*,\s*|\s+){_WORD}(?:\s+{_WORD}){{0,2}})?",
    re.IGNORECASE,
)
COORD_RES = (
    re.compile(r"\bLAT[\s:=]{0,3}(?P<lat>-?\d{1,2}\.\d{3,})[\s,;/]{1,5}LONG?[\s:=]{0,3}(?P<lon>-?\d{1,3}\.\d{3,})", re.I),
    re.compile(r"(?<![\d.])(?P<lat>-?\d{1,2}\.\d{4,})\s*[,/ ]\s*(?P<lon>-?\d{1,3}\.\d{4,})(?![\d.])"),
)
_SEGMENT_END = re.compile(r"[.;|\n]|\b(?:XST|X-ST|XSTR|CROSS\s+ST|MAP\s+REF|GRID)\b", re.I)


@dataclass
class Extracted:
    kind: str                 # "coords" | "street" | "place"
    lat: float | None = None
    lon: float | None = None
    number: str = ""          # house / RAPID number as sent to the geocoder
    street_words: list | None = None   # street name candidates, longest first
    street_type: str = ""
    locality: str = ""
    text: str = ""            # free text for "place"
    raw: str = ""             # the part of the message the location came from


def _clean_words(text: str) -> list[str]:
    return [w for w in re.split(r"\s+", text.strip()) if w]


def _locality(rest: str | None) -> str:
    if not rest:
        return ""
    words = []
    for w in _clean_words(rest.lstrip(" ,")):
        if w.upper().strip(".,") in TAIL_STOPWORDS or w.upper().strip(".,") in STREET_TYPES:
            break
        words.append(w.strip(".,"))
    return " ".join(words)


def _title(s: str) -> str:
    return " ".join(w[:1].upper() + w[1:].lower() if not w.isdigit() else w for w in s.split())


def _markers(markers: str) -> list[str]:
    return [m.strip() for m in (markers or "").split(",") if m.strip()]


def extract(message: str, markers: str = DEFAULTS["loc_markers"]) -> Extracted | None:
    """Find the most likely location in a page. Returns None if there isn't one."""
    if not message:
        return None
    text = re.sub(r"<[A-Z]{2,3}>", " ", message)   # multimon-ng control tokens

    for rx in COORD_RES:
        m = rx.search(text)
        if m:
            lat, lon = float(m.group("lat")), float(m.group("lon"))
            if -90 <= lat <= 90 and -180 <= lon <= 180 and not (abs(lat) < 1 and abs(lon) < 1):
                return Extracted("coords", lat=lat, lon=lon, raw=m.group(0))

    # Prefer the text after a location marker, e.g. "LOC: 12 SMITH ST" or "@ 12 SMITH ST".
    segment = None
    for mk in _markers(markers):
        i = text.upper().find(mk.upper())
        if i >= 0:
            after = text[i + len(mk):]
            end = _SEGMENT_END.search(after)
            segment = after[:end.start()] if end else after
            if segment.strip():
                break
            segment = None
    haystack = segment if segment is not None else text

    best = None
    for rx in (ADDRESS_RE, STATE_HWY_RE):
        for m in rx.finditer(haystack):
            # Prefer matches that carry a number, then the earliest one.
            has_num = bool(m.groupdict().get("rapid") or m.groupdict().get("num"))
            score = (1 if has_num else 0, -m.start())
            if best is None or score > best[0]:
                best = (score, rx, m)
    if best:
        _, rx, m = best
        number = m.group("rapid") or ""
        if not number and m.group("num"):
            number = re.split(r"\s*[/\-]\s*", m.group("num"))[-1]   # unit 2/34 -> 34
        if rx is STATE_HWY_RE:
            candidates = [f"State Highway {m.group('sh')}"]
            stype = ""
        else:
            words = _clean_words(m.group("name"))
            while len(words) > 1 and words[0].upper().strip(".,") in LEAD_STOPWORDS:
                words.pop(0)
            if words and words[0].upper().strip(".,") in LEAD_STOPWORDS and not number:
                words = []   # e.g. "FIRE ST" with no number is more likely noise than an address
            if not words:
                best = None
            else:
                stype = STREET_TYPES[m.group("type").lower()]
                candidates = [" ".join(words[i:]) for i in range(len(words))]
        if best:
            return Extracted("street", number=number,
                             street_words=[_title(c) for c in candidates],
                             street_type=stype, locality=_title(_locality(m.group("rest"))),
                             raw=m.group(0).strip())

    if segment is not None and segment.strip():
        place = segment.strip(" ,:-")
        place = re.sub(r"\s+", " ", place)[:80]
        if re.search(r"[A-Za-z]{3,}", place):
            return Extracted("place", text=_title(place), raw=segment.strip())
    return None


# --- geocoding ------------------------------------------------------------------

def _metres(lat1, lon1, lat2, lon2) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def radius_from_bbox(result: dict, lo: int, hi: int, default: int) -> int:
    try:
        s, n, w, e = (float(x) for x in result["boundingbox"])
        r = _metres(s, w, n, e) / 2
    except (KeyError, ValueError, TypeError):
        r = default
    return int(max(lo, min(hi, r)))


class Geocoder:
    """Nominatim-compatible lookups with a database cache and a 1-per-second limit."""

    _lock = threading.Lock()
    _last = 0.0

    def __init__(self, conn_factory, cfg: dict, fetch=None):
        self.conn_factory = conn_factory
        self.cfg = cfg
        self.fetch = fetch or self._http

    def _http(self, url: str) -> list:
        req = urllib.request.Request(url, headers={
            "User-Agent": f"MultipagePlus/{__version__} (+https://github.com/gomeznz/pagermon)",
            "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def lookup(self, params: dict) -> dict | None:
        params = {k: v for k, v in params.items() if v}
        key = json.dumps(params, sort_keys=True)
        conn = self.conn_factory()
        try:
            row = conn.execute("SELECT result, ts FROM geocode_cache WHERE key = ?", (key,)).fetchone()
            if row:
                age = time.time() - row["ts"]
                if row["result"] and age < 90 * 86400:
                    return json.loads(row["result"])
                if not row["result"] and age < 86400:
                    return None
            query = dict(params, format="jsonv2", limit="1", addressdetails="1")
            if self.cfg.get("loc_countries"):
                query["countrycodes"] = self.cfg["loc_countries"]
            if self.cfg.get("loc_email"):
                query["email"] = self.cfg["loc_email"]
            url = self.cfg.get("loc_geocoder") or DEFAULTS["loc_geocoder"]
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(query)
            with Geocoder._lock:
                wait = 1.1 - (time.time() - Geocoder._last)
                if wait > 0:
                    time.sleep(wait)
                try:
                    data = self.fetch(url)
                finally:
                    Geocoder._last = time.time()
            result = data[0] if isinstance(data, list) and data else None
            conn.execute("INSERT OR REPLACE INTO geocode_cache (key, result, ts) VALUES (?, ?, ?)",
                         (key, json.dumps(result) if result else "", time.time()))
            return result
        finally:
            conn.close()


def resolve(message: str, cfg: dict, geocoder: Geocoder) -> dict | None:
    """Location for a page as {lat, lon, radius_m, precision, label, display}, or None."""
    ext = extract(message, cfg.get("loc_markers", DEFAULTS["loc_markers"]))
    if not ext:
        return None
    if ext.kind == "coords":
        return {"lat": ext.lat, "lon": ext.lon, "radius_m": 0, "precision": "point",
                "label": f"{ext.lat:.5f}, {ext.lon:.5f}", "display": "", "query": ext.raw}
    region = (cfg.get("loc_region") or "").strip()

    if ext.kind == "street":
        cities = [c for c in dict.fromkeys([ext.locality, region]) if c] or [""]
        for name in ext.street_words:
            street = f"{name} {ext.street_type}".strip()
            for city in cities:
                params = {"street": f"{ext.number} {street}".strip()}
                if city:
                    params["city"] = city
                r = geocoder.lookup(params)
                if not r and ext.number:      # number unknown to the map: still find the street
                    r = geocoder.lookup(dict(params, street=street))
                if r:
                    got_number = bool(ext.number and (r.get("address") or {}).get("house_number"))
                    label = f"{ext.number + ' ' if ext.number else ''}{street}{', ' + city if city else ''}"
                    return {
                        "lat": float(r["lat"]), "lon": float(r["lon"]),
                        "radius_m": 0 if got_number else radius_from_bbox(r, 120, 2500, 400),
                        "precision": "point" if got_number else "area",
                        "label": label + ("" if got_number or not ext.number else " (number not found)"),
                        "display": r.get("display_name", ""), "query": ext.raw,
                    }
        place = ext.locality or region
        if place:
            r = geocoder.lookup({"q": place})
            if r:
                return {"lat": float(r["lat"]), "lon": float(r["lon"]),
                        "radius_m": radius_from_bbox(r, 400, 10000, 2000), "precision": "locality",
                        "label": place, "display": r.get("display_name", ""), "query": ext.raw}
        return None

    # A free-text place after a marker, e.g. "LOC: INVERCARGILL AIRPORT"
    q = ext.text + (f", {region}" if region and region.lower() not in ext.text.lower() else "")
    r = geocoder.lookup({"q": q}) or (geocoder.lookup({"q": ext.text}) if q != ext.text else None)
    if not r:
        return None
    if (r.get("address") or {}).get("house_number"):
        return {"lat": float(r["lat"]), "lon": float(r["lon"]), "radius_m": 0, "precision": "point",
                "label": ext.text, "display": r.get("display_name", ""), "query": ext.raw}
    return {"lat": float(r["lat"]), "lon": float(r["lon"]),
            "radius_m": radius_from_bbox(r, 150, 10000, 1000), "precision": "locality",
            "label": ext.text, "display": r.get("display_name", ""), "query": ext.raw}


class LocationWorker(threading.Thread):
    """Looks up page locations in the background so decoding never waits on the network."""

    def __init__(self, conn_factory, cfg: dict):
        super().__init__(name="locations", daemon=True)
        self.conn_factory = conn_factory
        self.cfg = cfg
        self.q: queue.Queue = queue.Queue(maxsize=500)
        self.stop_event = threading.Event()

    def enqueue(self, message_id: int, message: str) -> None:
        try:
            self.q.put_nowait((message_id, message))
        except queue.Full:
            log.warning("location queue full; skipping message %s", message_id)

    def stop(self) -> None:
        self.stop_event.set()
        self.q.put((None, None))

    def run(self) -> None:
        while not self.stop_event.is_set():
            mid, message = self.q.get()
            if mid is None:
                break
            try:
                res = resolve(message, self.cfg, Geocoder(self.conn_factory, self.cfg))
            except Exception as exc:
                log.warning("location lookup failed for message %s: %s", mid, exc)
                continue
            if not res:
                continue
            conn = self.conn_factory()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO message_locations (message_id, lat, lon, radius_m, precision, "
                    "label, display, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (mid, res["lat"], res["lon"], res["radius_m"], res["precision"],
                     res["label"][:120], res["display"][:300], time.time()))
            finally:
                conn.close()
