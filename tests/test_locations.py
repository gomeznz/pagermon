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
