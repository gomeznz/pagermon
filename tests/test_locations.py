import json
import threading
import time

import pytest

from app import db, locations
from app.locations import Geocoder, extract, resolve


def _fake_geocoder():
    """Pretend Nominatim: knows Yarrow Street (with number 115), Smith Street, and Invercargill."""
    calls = []

    def fetch(url):
        calls.append(url)
        from urllib.parse import parse_qs, urlparse
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        street = q.get("street", "").lower()
        if street == "115 yarrow street":
            return [{"lat": "-46.4119", "lon": "168.3520", "display_name": "115 Yarrow Street, Invercargill",
                     "address": {"house_number": "115", "road": "Yarrow Street"},
                     "boundingbox": ["-46.4120", "-46.4118", "168.3519", "168.3521"]}]
        if street.endswith("yarrow street"):      # other numbers: street only
            return [{"lat": "-46.4110", "lon": "168.3500", "display_name": "Yarrow Street, Invercargill",
                     "address": {"road": "Yarrow Street"},
                     "boundingbox": ["-46.4150", "-46.4070", "168.3400", "168.3600"]}]
        if street == "smith street":
            return [{"lat": "-46.4000", "lon": "168.3600", "display_name": "Smith Street",
                     "address": {"road": "Smith Street"}, "boundingbox": ["-46.401", "-46.399", "168.359", "168.361"]}]
        if q.get("q", "").lower().startswith("invercargill"):
            return [{"lat": "-46.4132", "lon": "168.3538", "display_name": "Invercargill, Southland",
                     "address": {"city": "Invercargill"}, "boundingbox": ["-46.47", "-46.36", "168.30", "168.43"]}]
        return []
    return fetch, calls


@pytest.fixture()
def geo(monkeypatch):
    db.init_db()
    conn = db.connect()
    conn.execute("DELETE FROM geocode_cache")
    conn.close()
    monkeypatch.setattr(Geocoder, "_last", 0.0)
    monkeypatch.setattr(locations.time, "sleep", lambda s: None)   # skip the 1 req/s wait in tests
    fetch, calls = _fake_geocoder()
    cfg = dict(locations.DEFAULTS, loc_enabled="1", loc_region="Invercargill")
    return Geocoder(db.connect, cfg, fetch=fetch), cfg, calls


def test_extract_variants():
    e = extract("MVA RAPID 1234 MAIN SOUTH RD WOODLANDS")
    assert (e.kind, e.number, e.street_words[0], e.street_type, e.locality) == \
        ("street", "1234", "Main South", "Road", "Woodlands")
    assert extract("ALARM 2/34A DEE STREET INVERCARGILL").number == "34A"
    assert extract("CAR FIRE SH1 EDENDALE").street_words == ["State Highway 1"]
    assert extract("MED LOC: BLUFF WHARF; PT 70YO").text == "Bluff Wharf"
    c = extract("LAT -46.4132 LON 168.3538 VESSEL ADRIFT")
    assert (c.kind, c.lat, c.lon) == ("coords", -46.4132, 168.3538)
    assert extract("Bench test 2400 baud: the quick brown fox") is None
    assert extract("STRUC1 HOUSE FIRE SMITH ST").street_words[0] == "Smith"   # dispatch words dropped


def test_numbered_address_is_a_point(geo):
    g, cfg, calls = geo
    r = resolve("STRUC1 HOUSE FIRE 115 YARROW ST INVERCARGILL", cfg, g)
    assert r["precision"] == "point" and r["radius_m"] == 0 and r["lat"] == -46.4119
    assert r["label"] == "115 Yarrow Street, Invercargill"


def test_no_number_is_an_area_with_radius(geo):
    g, cfg, calls = geo
    r = resolve("SCRUB FIRE YARROW ST", cfg, g)                 # falls back to the default region
    assert r["precision"] == "area" and 120 <= r["radius_m"] <= 2500


def test_unknown_number_falls_back_to_street_area(geo):
    g, cfg, calls = geo
    r = resolve("ALARM 999 YARROW STREET INVERCARGILL", cfg, g)
    assert r["precision"] == "area" and "number not found" in r["label"]


def test_town_only_is_a_locality(geo):
    g, cfg, calls = geo
    r = resolve("CALL LOC: INVERCARGILL", cfg, g)
    assert r["precision"] == "locality" and r["radius_m"] >= 400


def test_cache_avoids_repeat_requests(geo):
    g, cfg, calls = geo
    resolve("FIRE 115 YARROW ST INVERCARGILL", cfg, g)
    n = len(calls)
    resolve("FIRE 115 YARROW ST INVERCARGILL", cfg, g)
    assert len(calls) == n


def test_worker_stores_location(geo):
    g, cfg, calls = geo
    conn = db.connect()
    mid = conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                       "VALUES (?, 'T', 'POCSAG1200', '1500', 'alpha', '115 YARROW ST INVERCARGILL')",
                       (time.time(),)).lastrowid
    w = locations.LocationWorker(db.connect, cfg)
    orig = Geocoder.__init__
    def init(self, cf, c, fetch=None):
        orig(self, cf, c, fetch=g.fetch)
    Geocoder.__init__ = init
    try:
        w.start()
        w.enqueue(mid, "115 YARROW ST INVERCARGILL")
        for _ in range(50):
            row = conn.execute("SELECT * FROM message_locations WHERE message_id = ?", (mid,)).fetchone()
            if row:
                break
            threading.Event().wait(0.05)   # time.sleep is stubbed out by the fixture
    finally:
        w.stop()
        Geocoder.__init__ = orig
    assert row and row["precision"] == "point"
    conn.close()


# --- New Zealand only ---------------------------------------------------------

@pytest.mark.parametrize("name, lat, lon, inside", [
    ("Auckland", -36.85, 174.76, True),
    ("Invercargill", -46.41, 168.35, True),
    ("Cape Reinga", -34.43, 172.68, True),
    ("Oban, Stewart Island", -46.90, 168.13, True),
    ("Waitangi, Chatham Islands", -43.95, -176.56, True),
    ("Raoul Island, Kermadecs", -29.27, -177.92, True),
    ("Campbell Island", -52.54, 169.15, True),
    ("Sydney", -33.87, 151.21, False),
    ("Hobart", -42.88, 147.33, False),
    ("Norfolk Island", -29.04, 167.95, False),
    ("Lord Howe Island", -31.55, 159.08, False),
    ("Noumea", -22.27, 166.45, False),
    ("Suva, Fiji", -18.14, 178.44, False),
    ("Inverness, Scotland", 57.48, -4.22, False),
])
def test_in_nz(name, lat, lon, inside):
    assert locations.in_nz(lat, lon) is inside, name


def _overseas_fetch(calls):
    def fetch(url):
        calls.append(url)
        return [{"lat": "-33.8688", "lon": "151.2093", "display_name": "George Street, Sydney, Australia",
                 "address": {"road": "George Street", "country_code": "au"}, "boundingbox": ["-33.9", "-33.8", "151.2", "151.3"]}]
    return fetch


def test_overseas_geocoder_result_is_ignored(monkeypatch):
    conn = db.connect()
    conn.execute("DELETE FROM geocode_cache")
    conn.close()
    calls = []
    cfg = dict(locations.DEFAULTS, loc_countries="")       # even with the old setting cleared
    geo = Geocoder(db.connect, cfg, fetch=_overseas_fetch(calls))
    notes = []
    assert resolve("CAR FIRE 5 GEORGE ST", cfg, geo, notes) is None
    assert "countrycodes=nz" in calls[0]
    assert "Sydney" in geo.rejected


def test_overseas_coordinates_ignored_with_reason():
    notes = []
    assert resolve("MEET AT -33.8688, 151.2093 NOW", dict(locations.DEFAULTS), None, notes) is None
    assert notes and "outside New Zealand" in notes[0]
    ok = resolve("MEET AT -46.4119, 168.3520 NOW", dict(locations.DEFAULTS), None)
    assert ok and ok["precision"] == "point"


def test_cached_overseas_result_not_used():
    conn = db.connect()
    key = json.dumps({"q": "Somewhere"}, sort_keys=True)
    conn.execute("INSERT OR REPLACE INTO geocode_cache (key, result, ts) VALUES (?, ?, ?)",
                 (key, json.dumps({"lat": "51.5", "lon": "-0.12", "display_name": "London"}), time.time()))
    conn.close()
    geo = Geocoder(db.connect, dict(locations.DEFAULTS), fetch=lambda url: [])
    assert geo.lookup({"q": "Somewhere"}) is None


def test_purge_outside_nz():
    conn = db.connect()
    now = time.time()
    ids = []
    for msg in ("in nz", "in sydney"):
        ids.append(conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                                "VALUES (?, 'T', 'POCSAG1200', '42', 'alpha', ?)", (now, msg)).lastrowid)
    conn.execute("INSERT INTO message_locations (message_id, lat, lon, precision, created) VALUES (?, -46.41, 168.35, 'point', ?)", (ids[0], now))
    conn.execute("INSERT INTO message_locations (message_id, lat, lon, precision, created) VALUES (?, -33.87, 151.21, 'point', ?)", (ids[1], now))
    conn.execute("INSERT OR REPLACE INTO geocode_cache (key, result, ts) VALUES ('k-au', ?, ?)",
                 (json.dumps({"lat": "-33.87", "lon": "151.21"}), now))
    conn.execute("INSERT OR REPLACE INTO geocode_cache (key, result, ts) VALUES ('k-nz', ?, ?)",
                 (json.dumps({"lat": "-46.41", "lon": "168.35"}), now))
    assert locations.purge_outside(conn, ["nz"]) >= 1
    kept = {r["message_id"] for r in conn.execute("SELECT message_id FROM message_locations")}
    assert ids[0] in kept and ids[1] not in kept
    keys = {r["key"] for r in conn.execute("SELECT key FROM geocode_cache")}
    assert "k-nz" in keys and "k-au" not in keys
    conn.close()


def test_parse_countries():
    assert locations.parse_countries("") == ["nz"] and locations.parse_countries(None) == ["nz"]
    assert locations.parse_countries("NZ, au;au  fj") == ["nz", "au", "fj"]
    assert locations.parse_countries("new zealand") == ["nz"]          # junk words ignored → default
    assert locations.countries_text(["nz", "au", "fj"]) == "New Zealand, Australia and Fiji"


def test_several_countries():
    both = ["nz", "au"]
    assert locations.in_countries(-33.87, 151.21, both) is True        # Sydney
    assert locations.in_countries(-46.41, 168.35, both) is True        # Invercargill
    assert locations.in_countries(-29.04, 167.95, both) is False       # Norfolk Island: neither
    # a country with no outline: points can't be judged, so they aren't thrown away
    assert locations.in_countries(-18.14, 178.44, ["nz", "fj"]) is None
    # geocoder answers that name their country are judged by that
    assert locations.result_ok({"lat": "-18.14", "lon": "178.44", "address": {"country_code": "fj"}}, ["nz", "fj"])
    assert not locations.result_ok({"lat": "-33.87", "lon": "151.21", "address": {"country_code": "au"}}, ["nz"])
    # coordinates in a page follow the list
    cfg = dict(locations.DEFAULTS, loc_countries="nz,au")
    assert resolve("MEET AT -33.8688, 151.2093 NOW", cfg, None)["precision"] == "point"


def test_geocoder_sends_all_listed_countries_and_keeps_caches_apart():
    conn = db.connect()
    conn.execute("DELETE FROM geocode_cache")
    conn.close()
    calls = []
    cfg = dict(locations.DEFAULTS, loc_countries="nz,au")
    geo = Geocoder(db.connect, cfg, fetch=_overseas_fetch(calls))
    r = resolve("CAR FIRE 5 GEORGE ST", cfg, geo)
    assert r and "countrycodes=nz%2Cau" in calls[0]                    # Sydney accepted for nz,au
    # the same lookup with NZ only is a separate cache entry, and Sydney is rejected
    nz = dict(locations.DEFAULTS, loc_countries="nz")
    assert resolve("CAR FIRE 5 GEORGE ST", nz, Geocoder(db.connect, nz, fetch=_overseas_fetch(calls))) is None
