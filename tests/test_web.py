import re
import time

import pytest
from fastapi.testclient import TestClient

from app import auth, db, web


@pytest.fixture(scope="module")
def app():
    application = web.create_app()
    conn = db.connect()
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM messages")
    for name, role, filt in (("alex", "admin", ""), ("viewer1", "viewer", "1000-1999, 5555")):
        conn.execute(
            "INSERT INTO users (username, pw_hash, role, capcode_filter, created_at) VALUES (?,?,?,?,?)",
            (name, auth.hash_password("correct horse battery"), role, filt, time.time()))
    for cap, msg in (("1500", "in range"), ("5555", "exact"), ("9999", "hidden from viewer")):
        conn.execute(
            "INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
            "VALUES (?, 'Test', 'POCSAG1200', ?, 'alpha', ?)", (time.time(), cap, msg))
    conn.close()
    return application


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def login(client, username, password="correct horse battery"):
    r = client.get("/login")
    token = csrf_of(r.text)
    return client.post("/login", data={"username": username, "password": password,
                                       "csrf": token, "next": "/"}, follow_redirects=False)


def test_requires_login(app):
    c = TestClient(app)
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert c.get("/api/messages").status_code == 401


def test_login_and_live(app):
    c = TestClient(app)
    r = login(c, "alex")
    assert r.status_code == 303 and r.headers["location"] == "/"
    r = c.get("/")
    assert r.status_code == 200 and "Decoder" in r.text or "Live" in r.text
    assert "Content-Security-Policy" in r.headers


def test_bad_password_and_lockout(app):
    c = TestClient(app)
    for _ in range(5):
        r = login(c, "lockme", "wrong password!")
        assert r.headers["location"].startswith("/login")
    r = login(c, "lockme", "wrong password!")
    r = c.get("/login")
    assert "Too many failed attempts" in r.text
    web.limiter.clear("u:lockme", "ip:testclient")


def test_login_requires_csrf(app):
    c = TestClient(app)
    c.get("/login")
    r = c.post("/login", data={"username": "alex", "password": "correct horse battery"},
               follow_redirects=False)
    assert r.status_code == 403


def test_viewer_filter_and_forbidden(app):
    c = TestClient(app)
    login(c, "viewer1")
    msgs = c.get("/api/messages").json()["messages"]
    caps = sorted(m["capcode"] for m in msgs)
    assert caps == ["1500", "5555"]
    assert "hidden from viewer" not in c.get("/history").text
    assert c.get("/config").status_code == 403
    assert c.get("/users").status_code == 403
    csv_text = c.get("/history.csv").text
    assert "9999" not in csv_text and "1500" in csv_text


def test_admin_sees_all_and_search(app):
    c = TestClient(app)
    login(c, "alex")
    assert len(c.get("/api/messages").json()["messages"]) == 3
    r = c.get("/history", params={"q": "exact"})
    assert "exact" in r.text and "in range" not in r.text
    r = c.get("/history", params={"q": "%"})  # LIKE wildcard is escaped
    assert "0 messages" in r.text


def test_channel_crud_bumps_config_version(app):
    c = TestClient(app)
    login(c, "alex")
    token = csrf_of(c.get("/config").text)
    conn = db.connect()
    before = int(db.get_setting(conn, "config_version"))
    r = c.post("/config/channel", data={
        "csrf": token, "name": "Bench", "freq_mhz": "157.45", "device": "0", "gain": "auto",
        "ppm": "2", "squelch": "0", "protocols": ["POCSAG1200", "FLEX"], "pocsag_mode": "auto",
        "enabled": "1"}, follow_redirects=False)
    assert r.status_code == 303
    row = conn.execute("SELECT * FROM channels WHERE name = 'Bench'").fetchone()
    assert row["freq_hz"] == 157450000 and row["protocols"] == "POCSAG1200,FLEX"
    assert int(db.get_setting(conn, "config_version")) == before + 1
    # bad input is rejected
    c.post("/config/channel", data={"csrf": token, "name": "X", "freq_mhz": "5",
                                    "protocols": ["FLEX"], "extra_rtl": "; rm -rf /"})
    assert conn.execute("SELECT COUNT(*) FROM channels WHERE name = 'X'").fetchone()[0] == 0
    conn.close()


def test_cannot_remove_last_admin(app):
    c = TestClient(app)
    login(c, "alex")
    token = csrf_of(c.get("/users").text)
    conn = db.connect()
    uid = conn.execute("SELECT id FROM users WHERE username='alex'").fetchone()[0]
    c.post(f"/users/{uid}/update", data={"csrf": token, "role": "viewer", "active": "1"})
    assert conn.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()[0] == "admin"
    conn.close()


def test_password_reset_signs_out_other_sessions(app):
    a = TestClient(app)
    login(a, "alex")
    v = TestClient(app)
    login(v, "viewer1")
    assert v.get("/api/messages").status_code == 200
    token = csrf_of(a.get("/users").text)
    conn = db.connect()
    vid = conn.execute("SELECT id FROM users WHERE username='viewer1'").fetchone()[0]
    a.post(f"/users/{vid}/password", data={"csrf": token, "password": "a brand new password"})
    assert v.get("/api/messages").status_code == 401
    conn.close()


def test_websocket_rejects_cross_origin(app):
    c = TestClient(app)
    login(c, "alex")
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/ws", headers={"origin": "http://evil.example"}) as ws:
            ws.receive_json()


def test_websocket_feed(app):
    c = TestClient(app)
    login(c, "viewer1", "a brand new password")  # reset by the previous test
    with c.websocket_connect("/ws", headers={"origin": "http://testserver"}) as ws:
        first = ws.receive_json()
        assert first["type"] == "messages"
        assert sorted(m["capcode"] for m in first["messages"]) == ["1500", "5555"]
        status = ws.receive_json()
        assert status["type"] == "status"


def test_safe_next():
    assert web._safe_next("//evil.com") == "/"
    assert web._safe_next("https://evil.com") == "/"
    assert web._safe_next("/history?x=1") == "/history?x=1"


def test_csv_formula_guard():
    assert web._csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert web._csv_safe("hello") == "hello"


def test_suppress_alias_and_flag(app):
    c = TestClient(app)
    login(c, "alex")
    token = csrf_of(c.get("/config").text)
    # label is optional when suppressing; alert is forced off
    r = c.post("/config/alias", data={"csrf": token, "capcode": "0009999", "label": "",
                                      "suppress": "1", "alert": "1"}, follow_redirects=False)
    assert r.status_code == 303
    conn = db.connect()
    row = conn.execute("SELECT * FROM aliases WHERE capcode = '9999'").fetchone()
    assert row["suppress"] == 1 and row["alert"] == 0
    msgs = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert msgs["9999"]["suppressed"] == 1 and msgs["1500"]["suppressed"] == 0
    assert "suppressed" in c.get("/history").text
    assert ",yes," in c.get("/history.csv").text
    # toggle off again
    c.post(f"/config/alias/{row['id']}/suppress", data={"csrf": token})
    assert conn.execute("SELECT suppress FROM aliases WHERE id = ?", (row["id"],)).fetchone()[0] == 0
    # no label and no suppress is refused
    c.post("/config/alias", data={"csrf": token, "capcode": "4242", "label": ""})
    assert conn.execute("SELECT COUNT(*) FROM aliases WHERE capcode = '4242'").fetchone()[0] == 0
    conn.close()


def test_migration_adds_suppress_column(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE aliases (id INTEGER PRIMARY KEY, capcode TEXT NOT NULL UNIQUE, "
                "label TEXT NOT NULL, alert INTEGER NOT NULL DEFAULT 0)")
    old.execute("INSERT INTO aliases (capcode, label) VALUES ('1', 'old')")
    old.commit(); old.close()
    db.init_db(path)
    conn = db.connect(path)
    assert conn.execute("SELECT suppress FROM aliases WHERE capcode='1'").fetchone()[0] == 0
    conn.close()


def test_capcodes_page(app):
    c = TestClient(app)
    login(c, "alex")
    r = c.get("/capcodes")
    assert r.status_code == 200 and "Add capcode" in r.text and "Last seen" in r.text
    assert "capcode-form" not in c.get("/config").text  # moved off Config
    r = c.get("/capcodes", params={"edit": "1500"})  # unknown capcode pre-fills the form
    assert 'value="1500"' in r.text
    token = csrf_of(r.text)
    r = c.post("/config/alias", data={"csrf": token, "capcode": "1500", "label": "Bench"},
               follow_redirects=False)
    assert r.headers["location"] == "/capcodes"
    assert "Edit 1500" in c.get("/capcodes", params={"edit": "1500"}).text
    assert 'href="/capcodes?edit=1500' in c.get("/history").text


def test_capcodes_admin_only(app):
    c = TestClient(app)
    login(c, "viewer1", "a brand new password")
    assert c.get("/capcodes").status_code == 403
    hist = c.get("/history").text
    assert 'href="/my?edit=' in hist and 'href="/capcodes?edit=' not in hist


def test_capcode_colour(app):
    c = TestClient(app)
    login(c, "alex")
    token = csrf_of(c.get("/capcodes").text)
    c.post("/config/alias", data={"csrf": token, "capcode": "5555", "label": "", "colour": "blue"})
    conn = db.connect()
    assert conn.execute("SELECT colour FROM aliases WHERE capcode='5555'").fetchone()[0] == "blue"
    msgs = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert msgs["5555"]["colour"] == "blue"
    assert "c-blue" in c.get("/history").text
    # unknown colour names are dropped, never written into the page
    c.post("/config/alias", data={"csrf": token, "capcode": "5555", "label": "x", "colour": "evil\"><script>"})
    assert conn.execute("SELECT colour FROM aliases WHERE capcode='5555'").fetchone()[0] == ""
    conn.close()


def test_debug_console(app):
    conn = db.connect()
    conn.execute("DELETE FROM debug_log")
    conn.executemany(
        "INSERT INTO debug_log (ts, channel_id, channel_name, source, kind, text) VALUES (?,?,?,?,?,?)",
        [(time.time(), 1, "Bench", "multimon", "parsed", "POCSAG1200: Address: 1  Function: 3  Alpha:   hi"),
         (time.time(), 1, "Bench", "multimon", "unparsed", "FLEX|weird|line"),
         (time.time(), 1, "Bench", "rtl_fm", "stderr", "Found 1 device(s)")])
    c = TestClient(app)
    login(c, "alex")
    assert 'href="/debug" target="_blank"' in c.get("/config").text
    assert c.get("/debug").status_code == 200
    lines = c.get("/api/debug").json()["lines"]
    assert [l["kind"] for l in lines] == ["parsed", "unparsed", "stderr"]
    assert c.get("/api/debug", params={"after": lines[1]["id"]}).json()["lines"][0]["source"] == "rtl_fm"
    assert "FLEX|weird|line" in c.get("/debug.txt").text
    token = csrf_of(c.get("/debug").text)
    assert c.post("/debug/clear", data={"csrf": "nope"}).status_code == 403
    assert c.post("/debug/clear", data={"csrf": token}).status_code == 200
    assert c.get("/api/debug").json()["lines"] == []
    # viewers can't see it
    v = TestClient(app)
    login(v, "viewer1", "a brand new password")
    assert v.get("/debug").status_code == 403 and v.get("/api/debug").status_code == 403
    conn.close()


def test_keywords(app):
    conn = db.connect()
    conn.execute("DELETE FROM keywords")
    conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                 "VALUES (?, 'Test', 'POCSAG1200', '1600', 'alpha', 'Generator FAULT at site 4')", (time.time(),))
    conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                 "VALUES (?, 'Test', 'POCSAG1200', '1601', 'alpha', 'routine heartbeat')", (time.time(),))
    c = TestClient(app)
    login(c, "alex")
    page = c.get("/capcodes")
    assert 'id="keywords"' in page.text and "Add keyword" in page.text
    token = csrf_of(page.text)
    # needs at least one action
    c.post("/config/keyword", data={"csrf": token, "keyword": "fault"})
    assert conn.execute("SELECT COUNT(*) FROM keywords").fetchone()[0] == 0
    c.post("/config/keyword", data={"csrf": token, "keyword": "fault", "alert": "1", "colour": "red"})
    c.post("/config/keyword", data={"csrf": token, "keyword": "heartbeat", "suppress": "1"})
    # duplicate (case-insensitive) refused
    c.post("/config/keyword", data={"csrf": token, "keyword": "FAULT", "suppress": "1"})
    assert conn.execute("SELECT COUNT(*) FROM keywords").fetchone()[0] == 2
    msgs = {m["capcode"]: m for m in c.get("/api/messages", params={"limit": 500}).json()["messages"]}
    assert msgs["1600"]["alert"] == 1 and msgs["1600"]["colour"] == "red"
    assert msgs["1600"]["keywords"] == ["fault"] and msgs["1600"]["spans"] == [[10, 15, "red"]]
    assert msgs["1601"]["suppressed"] == 1
    hist = c.get("/history", params={"q": "FAULT"}).text
    assert '<mark class="kw c-red">FAULT</mark>' in hist and "alert-tag" in hist
    assert "fault" in c.get("/history.csv", params={"q": "FAULT"}).text.split("\n")[1]
    # edit, toggle, delete
    kid = conn.execute("SELECT id FROM keywords WHERE keyword='heartbeat'").fetchone()[0]
    assert "Edit &ldquo;heartbeat&rdquo;" in c.get("/capcodes", params={"kw": kid}).text
    c.post(f"/config/keyword/{kid}/suppress", data={"csrf": token})
    assert conn.execute("SELECT suppress FROM keywords WHERE id=?", (kid,)).fetchone()[0] == 0
    c.post(f"/config/keyword/{kid}/delete", data={"csrf": token})
    assert conn.execute("SELECT COUNT(*) FROM keywords WHERE id=?", (kid,)).fetchone()[0] == 0
    conn.close()


def test_kiosk(app):
    conn = db.connect()
    conn.execute("DELETE FROM kiosks")
    conn.execute("INSERT OR REPLACE INTO aliases (capcode, label, alert, suppress, colour) "
                 "VALUES ('1601', '', 0, 1, '')")
    c = TestClient(app)
    login(c, "alex")
    token = csrf_of(c.get("/config").text)
    c.post("/config/kiosk", data={"csrf": token, "name": "Workshop", "capcode_filter": "1600-1601"})
    k = conn.execute("SELECT * FROM kiosks WHERE name='Workshop'").fetchone()
    assert k and len(k["token"]) >= 30
    assert f"/kiosk/{k['token']}" in c.get("/config").text

    anon = TestClient(app)  # no login
    r = anon.get(f"/kiosk/{k['token']}")
    assert r.status_code == 200 and "Workshop" in r.text and "kiosk.js" in r.text
    assert anon.get("/kiosk/not-a-real-token").status_code == 404
    with anon.websocket_connect(f"/kiosk/{k['token']}/ws", headers={"origin": "http://testserver"}) as ws:
        msgs = ws.receive_json()["messages"]
        caps = {m["capcode"] for m in msgs}
        assert caps == {"1600"}  # filter applied, suppressed 1601 never sent
        assert ws.receive_json()["type"] == "status"
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with anon.websocket_connect(f"/kiosk/{k['token']}/ws", headers={"origin": "http://evil.example"}) as ws:
            ws.receive_json()
    # the kiosk link grants nothing else
    assert anon.get("/api/messages").status_code == 401

    # new link revokes the old one; disable takes it offline
    c.post(f"/config/kiosk/{k['id']}/newlink", data={"csrf": token})
    k2 = conn.execute("SELECT * FROM kiosks WHERE id=?", (k["id"],)).fetchone()
    assert k2["token"] != k["token"] and anon.get(f"/kiosk/{k['token']}").status_code == 404
    c.post(f"/config/kiosk/{k['id']}/toggle", data={"csrf": token})
    assert anon.get(f"/kiosk/{k2['token']}").status_code == 404
    c.post(f"/config/kiosk/{k['id']}/delete", data={"csrf": token})
    assert conn.execute("SELECT COUNT(*) FROM kiosks").fetchone()[0] == 0
    # viewers can't make kiosks
    v = TestClient(app)
    login(v, "viewer1", "a brand new password")
    assert v.post("/config/kiosk", data={"csrf": "x", "name": "nope"}).status_code == 403
    conn.close()


def test_kiosk_routing(app):
    conn = db.connect()
    for tbl in ("kiosks", "kiosk_routes", "keywords"):
        conn.execute(f"DELETE FROM {tbl}")
    now = time.time()
    for cap, msg in (("3001", "routine check"), ("3002", "FIRE at depot"), ("3003", "noise")):
        conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                     "VALUES (?, 'Test', 'POCSAG1200', ?, 'alpha', ?)", (now, cap, msg))
    c = TestClient(app)
    login(c, "alex")
    token = csrf_of(c.get("/config").text)
    c.post("/config/kiosk", data={"csrf": token, "name": "Board", "mode": "forwarded"})
    c.post("/config/kiosk", data={"csrf": token, "name": "Wall", "capcode_filter": "3001-3003"})
    board = conn.execute("SELECT * FROM kiosks WHERE name='Board'").fetchone()
    wall = conn.execute("SELECT * FROM kiosks WHERE name='Wall'").fetchone()
    assert board["mode"] == "forwarded"
    page = c.get("/capcodes")
    assert 'name="kiosk_0"' in page.text and f'name="kiosk_{board["id"]}"' in page.text
    # capcode 3001: forward to Board only. Keyword "fire": alert on all kiosks.
    # Capcode 3003: suppress on Wall only (label-less, kiosk-only rule is allowed).
    c.post("/config/alias", data={"csrf": token, "capcode": "3001", "label": "Routine",
                                  f"kiosk_{board['id']}": "forward"})
    c.post("/config/keyword", data={"csrf": token, "keyword": "fire", "kiosk_0": "alert"})
    c.post("/config/alias", data={"csrf": token, "capcode": "3003", "label": "",
                                  f"kiosk_{wall['id']}": "suppress"})
    assert conn.execute("SELECT COUNT(*) FROM kiosk_routes").fetchone()[0] == 3
    page = c.get("/capcodes").text
    assert "route-chip r-forward" in page and "All kiosks" in page

    anon = TestClient(app)
    def shown(k):
        with anon.websocket_connect(f"/kiosk/{k['token']}/ws", headers={"origin": "http://testserver"}) as ws:
            return {m["capcode"]: m["alert"] for m in ws.receive_json()["messages"]
                    if m["capcode"] in ("3001", "3002", "3003")}
    assert shown(board) == {"3001": 0, "3002": 1}          # only forwarded + alerted
    assert shown(wall) == {"3001": 0, "3002": 1}           # 3003 suppressed on Wall only
    # editing the capcode clears its old routes
    c.post("/config/alias", data={"csrf": token, "capcode": "3001", "label": "Routine"})
    assert shown(board) == {"3002": 1}
    # removing a kiosk removes its routes
    c.post(f"/config/kiosk/{wall['id']}/delete", data={"csrf": token})
    assert conn.execute("SELECT COUNT(*) FROM kiosk_routes WHERE kiosk_id=?", (wall["id"],)).fetchone()[0] == 0
    # kiosk settings can be edited
    c.post(f"/config/kiosk/{board['id']}/edit", data={"csrf": token, "name": "Board 2", "mode": "all", "theme": "light"})
    b2 = conn.execute("SELECT * FROM kiosks WHERE id=?", (board["id"],)).fetchone()
    assert (b2["name"], b2["mode"], b2["theme"]) == ("Board 2", "all", "light")
    conn.close()


def _reset_personal(conn):
    for tbl in ("user_aliases", "user_keywords", "user_routes", "kiosks", "kiosk_routes", "keywords"):
        conn.execute(f"DELETE FROM {tbl}")
    conn.execute("DELETE FROM aliases WHERE capcode IN ('1500', '5555', '9999')")


def test_personal_filters_only_affect_owner(app):
    conn = db.connect()
    _reset_personal(conn)
    v = TestClient(app)
    login(v, "viewer1", "a brand new password")      # filter: 1000-1999, 5555
    page = v.get("/my")
    assert page.status_code == 200 and "<h1>My capcodes</h1>" in page.text
    assert 'id="keywords"' in page.text and 'action="/my/capcode"' in page.text and "/config/alias" not in page.text
    kp = v.get("/my/kiosks")
    assert kp.status_code == 200 and "My kiosks &amp; alerts" in kp.text and 'name="notify_url"' in kp.text
    token = csrf_of(page.text)
    # outside the user's filter is refused
    v.post("/my/capcode", data={"csrf": token, "capcode": "9999", "label": "nope"})
    assert conn.execute("SELECT COUNT(*) FROM user_aliases").fetchone()[0] == 0
    v.post("/my/capcode", data={"csrf": token, "capcode": "1500", "label": "My bench", "colour": "purple"})
    v.post("/my/capcode", data={"csrf": token, "capcode": "5555", "suppress": "1"})
    v.post("/my/keyword", data={"csrf": token, "keyword": "range", "alert": "1", "colour": "red"})
    mine = {m["capcode"]: m for m in v.get("/api/messages").json()["messages"]}
    assert mine["1500"]["alias"] == "My bench"
    assert mine["1500"]["alert"] == 1 and mine["1500"]["colour"] == "red"   # keyword colour beats capcode colour
    assert [x[2] for x in mine["1500"]["spans"]] == ["red"]
    assert mine["5555"]["suppressed"] == 1
    # the admin's view is unchanged
    a = TestClient(app)
    login(a, "alex")
    theirs = {m["capcode"]: m for m in a.get("/api/messages").json()["messages"]}
    assert theirs["1500"]["alias"] in (None, "") and theirs["1500"]["alert"] == 0
    assert theirs["5555"]["suppressed"] == 0
    # edit / toggle / delete only work on your own rules
    rid = conn.execute("SELECT id FROM user_aliases WHERE capcode='5555'").fetchone()[0]
    atok = csrf_of(a.get("/my").text)
    a.post(f"/my/capcode/{rid}/delete", data={"csrf": atok})               # not alex's rule
    assert conn.execute("SELECT COUNT(*) FROM user_aliases WHERE id=?", (rid,)).fetchone()[0] == 1
    v.post(f"/my/capcode/{rid}/suppress", data={"csrf": token})
    assert conn.execute("SELECT suppress FROM user_aliases WHERE id=?", (rid,)).fetchone()[0] == 0
    v.post(f"/my/capcode/{rid}/delete", data={"csrf": token})
    assert conn.execute("SELECT COUNT(*) FROM user_aliases WHERE id=?", (rid,)).fetchone()[0] == 0
    conn.close()


def test_rule_edits_do_not_restart_radio(app):
    conn = db.connect()
    cv, rv = db.get_setting(conn, "config_version"), int(db.get_setting(conn, "rules_version"))
    a = TestClient(app)
    login(a, "alex")
    tok = csrf_of(a.get("/capcodes").text)
    a.post("/config/alias", data={"csrf": tok, "capcode": "4321", "label": "x"})
    a.post("/my/keyword", data={"csrf": tok, "keyword": "zebra", "colour": "blue"})
    assert db.get_setting(conn, "config_version") == cv
    assert int(db.get_setting(conn, "rules_version")) == rv + 2
    conn.close()


def test_personal_kiosks(app):
    conn = db.connect()
    _reset_personal(conn)
    vid = conn.execute("SELECT id FROM users WHERE username='viewer1'").fetchone()[0]
    conn.execute("UPDATE users SET max_kiosks = 1 WHERE id = ?", (vid,))
    v = TestClient(app)
    login(v, "viewer1", "a brand new password")
    token = csrf_of(v.get("/my").text)
    v.post("/my/kiosk", data={"csrf": token, "name": "Desk", "mode": "forwarded"})
    v.post("/my/kiosk", data={"csrf": token, "name": "Second"})            # over the limit
    ks = conn.execute("SELECT * FROM kiosks WHERE owner_id = ?", (vid,)).fetchall()
    assert [k["name"] for k in ks] == ["Desk"]
    desk = ks[0]
    # forward 1500 and (try to) 9999 to the kiosk — 9999 is outside viewer1's filter
    v.post("/my/capcode", data={"csrf": token, "capcode": "1500", "label": "Mine",
                                f"kiosk_{desk['id']}": "forward"})
    v.post("/my/keyword", data={"csrf": token, "keyword": "hidden", "kiosk_0": "alert"})
    anon = TestClient(app)
    with anon.websocket_connect(f"/kiosk/{desk['token']}/ws", headers={"origin": "http://testserver"}) as ws:
        msgs = ws.receive_json()["messages"]
    caps = {m["capcode"]: m for m in msgs}
    assert "1500" in caps and caps["1500"]["alias"] == "Mine"
    assert "9999" not in caps            # "hidden from viewer" matches the keyword but is outside the owner's filter
    # shared kiosk lists don't include personal kiosks; admin sees them separately
    a = TestClient(app)
    login(a, "alex")
    cfg = a.get("/config").text
    assert "Users' personal kiosks" in cfg and "Desk" in cfg
    assert f'name="kiosk_{desk["id"]}"' not in a.get("/capcodes").text
    # disabling the owner cuts the kiosk off
    conn.execute("UPDATE users SET active = 0 WHERE id = ?", (vid,))
    assert anon.get(f"/kiosk/{desk['token']}").status_code == 404
    conn.execute("UPDATE users SET active = 1 WHERE id = ?", (vid,))
    assert anon.get(f"/kiosk/{desk['token']}").status_code == 200
    # someone else can't manage it
    atok = csrf_of(cfg)
    a.post(f"/my/kiosk/{desk['id']}/delete", data={"csrf": atok})
    assert conn.execute("SELECT COUNT(*) FROM kiosks WHERE id=?", (desk["id"],)).fetchone()[0] == 1
    # admin's max-kiosks control
    a.post(f"/users/{vid}/update", data={"csrf": atok, "role": "viewer", "active": "1",
                                         "capcode_filter": "1000-1999, 5555", "max_kiosks": "0"})
    assert conn.execute("SELECT max_kiosks FROM users WHERE id=?", (vid,)).fetchone()[0] == 0
    conn.close()


def test_personal_alert_webhook(app, tmp_path):
    from app.decoder import Decoder
    from app.parser import parse_line
    conn = db.connect()
    _reset_personal(conn)
    vid = conn.execute("SELECT id FROM users WHERE username='viewer1'").fetchone()[0]
    conn.execute("UPDATE users SET notify_url = 'http://hook.invalid/me' WHERE id = ?", (vid,))
    conn.execute("INSERT INTO user_keywords (user_id, keyword, alert) VALUES (?, 'boiler', 1)", (vid,))
    sent = []
    import app.decoder as dec
    orig = dec.send_webhook
    dec.send_webhook = lambda url, payload: sent.append((url, payload))
    try:
        d = Decoder.__new__(Decoder)
        d.conn = conn
        d.loc_cfg, d.loc_worker = {}, None
        d.dedupe_seconds = 0
        d.recent = {}
        d.load_rules()
        ch = {"id": 1, "name": "Bench", "freq_hz": 157450000}
        d.store(ch, parse_line("POCSAG1200: Address: 1500  Function: 3  Alpha:   BOILER fault"), time.time())
        d.store(ch, parse_line("POCSAG1200: Address: 9999  Function: 3  Alpha:   boiler outside filter"), time.time())
        time.sleep(0.3)
    finally:
        dec.send_webhook = orig
        conn.execute("UPDATE users SET notify_url = '' WHERE id = ?", (vid,))
    assert [p["capcode"] for u, p in sent] == ["1500"] and sent[0][1]["user"] == "viewer1"
    conn.close()


def test_locations_on_live_history_map(app):
    conn = db.connect()
    now = time.time()
    m1 = conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                      "VALUES (?, 'T', 'POCSAG1200', '1500', 'alpha', 'FIRE 115 YARROW ST')", (now,)).lastrowid
    m2 = conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                      "VALUES (?, 'T', 'POCSAG1200', '9999', 'alpha', 'FIRE KEW RD')", (now,)).lastrowid
    for mid, prec, rad in ((m1, "point", 0), (m2, "area", 600)):
        conn.execute("INSERT INTO message_locations (message_id, lat, lon, radius_m, precision, label, display, created) "
                     "VALUES (?, -46.41, 168.35, ?, ?, 'Somewhere', '', ?)", (mid, rad, prec, now))
    v = TestClient(app)
    login(v, "viewer1", "a brand new password")   # can see 1000-1999, 5555 only
    data = v.get("/api/map", params={"hours": 1}).json()
    ids = [m["id"] for m in data["messages"]]
    assert m1 in ids and m2 not in ids                      # map respects the capcode filter
    loc = next(m for m in data["messages"] if m["id"] == m1)["loc"]
    assert loc["precision"] == "point" and loc["lat"] == -46.41
    assert 'href="/map?focus=%d"' % m1 in v.get("/history").text
    assert v.get("/map").status_code == 200
    # admin settings + tester (with a fake geocoder)
    a = TestClient(app)
    login(a, "alex")
    tok = csrf_of(a.get("/config").text)
    a.post("/config/locations", data={"csrf": tok, "loc_enabled": "1", "loc_region": "Invercargill",
                                      "loc_countries": "nz", "loc_markers": "LOC:, @",
                                      "map_tiles": "https://tile.openstreetmap.org/{z}/{x}/{y}.png"})
    assert db.get_setting(conn, "loc_enabled") == "1" and db.get_setting(conn, "loc_region") == "Invercargill"
    from app.locations import Geocoder
    orig = Geocoder._http
    Geocoder._http = lambda self, url: [{"lat": "-46.4", "lon": "168.3", "display_name": "x",
                                         "address": {"house_number": "12"}, "boundingbox": ["-46.41", "-46.39", "168.29", "168.31"]}]
    try:
        page = a.post("/config/locations/test", data={"csrf": tok, "sample": "HOUSE FIRE 12 TEST ST"}).text
    finally:
        Geocoder._http = orig
    assert "Exact address" in page and "number 12" in page
    # live websocket sends an update when a location arrives after the page
    with a.websocket_connect("/ws", headers={"origin": "http://testserver"}) as ws:
        ws.receive_json(); ws.receive_json()
        m3 = conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                          "VALUES (?, 'T', 'POCSAG1200', '1501', 'alpha', 'later')", (time.time(),)).lastrowid
        got = ws.receive_json()
        assert got["type"] == "messages" and got["messages"][-1]["loc"] is None
        conn.execute("INSERT INTO message_locations (message_id, lat, lon, radius_m, precision, label, display, created) "
                     "VALUES (?, -46.4, 168.3, 0, 'point', 'Later St', '', ?)", (m3, time.time()))
        for _ in range(5):
            got = ws.receive_json()
            if got["type"] == "update":
                break
        assert got["type"] == "update" and got["messages"][0]["loc"]["label"] == "Later St"
    conn.close()


def test_capcode_service_quick_label(app):
    c = TestClient(app)
    login(c, "alex")
    conn = db.connect()
    conn.execute("DELETE FROM aliases WHERE capcode IN ('1500', '9999')")
    token = csrf_of(c.get("/capcodes").text)
    # saving with only a service labels the capcode after it
    c.post("/config/alias", data={"csrf": token, "capcode": "1500", "service": "ambulance"})
    row = conn.execute("SELECT * FROM aliases WHERE capcode='1500'").fetchone()
    assert row["service"] == "ambulance" and row["label"] == "Ambulance"
    # one-click switch: the auto label follows; a custom label is kept
    c.post(f"/config/alias/{row['id']}/service", data={"csrf": token, "service": "fire"})
    row = conn.execute("SELECT * FROM aliases WHERE capcode='1500'").fetchone()
    assert row["service"] == "fire" and row["label"] == "Fire"
    conn.execute("UPDATE aliases SET label = 'Station 41' WHERE id = ?", (row["id"],))
    c.post(f"/config/alias/{row['id']}/service", data={"csrf": token, "service": "police"})
    row = conn.execute("SELECT * FROM aliases WHERE capcode='1500'").fetchone()
    assert row["service"] == "police" and row["label"] == "Station 41"
    msgs = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert msgs["1500"]["service"] == "police" and msgs["5555"]["service"] in ("", None)
    page = c.get("/capcodes").text
    assert "services.svg#svc-police" in page and 'aria-pressed="true"' in page
    # picking the current service again clears it; junk values never stick
    c.post(f"/config/alias/{row['id']}/service", data={"csrf": token, "service": "police"})
    assert conn.execute("SELECT service FROM aliases WHERE id=?", (row["id"],)).fetchone()[0] == ""
    c.post(f"/config/alias/{row['id']}/service", data={"csrf": token, "service": "evil\"><x>"})
    assert conn.execute("SELECT service FROM aliases WHERE id=?", (row["id"],)).fetchone()[0] == ""
    # personal service overrides the shared one, only for that user
    v = TestClient(app)
    login(v, "viewer1", "a brand new password")
    vt = csrf_of(v.get("/my").text)
    c.post(f"/config/alias/{row['id']}/service", data={"csrf": token, "service": "fire"})
    v.post("/my/capcode", data={"csrf": vt, "capcode": "1500", "service": "ambulance"})
    vm = {m["capcode"]: m for m in v.get("/api/messages").json()["messages"]}
    am = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert vm["1500"]["service"] == "ambulance" and am["1500"]["service"] == "fire"
    uid = conn.execute("SELECT id FROM user_aliases WHERE capcode='1500'").fetchone()[0]
    v.post(f"/my/capcode/{uid}/service", data={"csrf": vt, "service": "ambulance"})
    vm = {m["capcode"]: m for m in v.get("/api/messages").json()["messages"]}
    assert vm["1500"]["service"] == "fire"   # cleared personal → shared shows through
    # viewers can't change the shared setting
    assert v.post(f"/config/alias/{row['id']}/service", data={"csrf": vt, "service": "police"}).status_code == 403
    conn.close()


def test_migration_adds_service_column(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript("CREATE TABLE aliases (id INTEGER PRIMARY KEY, capcode TEXT NOT NULL UNIQUE, "
                      "label TEXT NOT NULL, alert INTEGER NOT NULL DEFAULT 0);"
                      "CREATE TABLE user_aliases (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, "
                      "capcode TEXT NOT NULL, label TEXT NOT NULL DEFAULT '');")
    old.close()
    monkeypatch.setattr(db.settings, "DB_PATH", str(path), raising=False)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    db._migrate(conn)
    assert "service" in {r["name"] for r in conn.execute("PRAGMA table_info(aliases)")}
    assert "service" in {r["name"] for r in conn.execute("PRAGMA table_info(user_aliases)")}
    conn.close()


def test_keyword_service(app):
    c = TestClient(app)
    login(c, "alex")
    conn = db.connect()
    conn.execute("DELETE FROM keywords")
    conn.execute("INSERT INTO messages (ts, channel_name, protocol, capcode, msg_type, message) "
                 "VALUES (?, 'Test', 'POCSAG1200', '1501', 'alpha', 'STRUCTURE FIRE MAIN ST')", (time.time(),))
    token = csrf_of(c.get("/capcodes").text)
    # a keyword with only a service is enough to save
    c.post("/config/keyword", data={"csrf": token, "keyword": "structure fire", "match": "word", "service": "fire"})
    kw = conn.execute("SELECT * FROM keywords WHERE keyword='structure fire'").fetchone()
    assert kw["service"] == "fire"
    msgs = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert msgs["1501"]["service"] == "fire"
    # the keyword's service beats the capcode's
    c.post("/config/alias", data={"csrf": token, "capcode": "1501", "label": "Mixed", "service": "police"})
    msgs = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert msgs["1501"]["service"] == "fire"
    page = c.get("/capcodes").text
    assert f'/config/keyword/{kw["id"]}/service' in page
    # quick toggle off → capcode's service shows through; junk ignored
    c.post(f"/config/keyword/{kw['id']}/service", data={"csrf": token, "service": "fire"})
    assert conn.execute("SELECT service FROM keywords WHERE id=?", (kw["id"],)).fetchone()[0] == ""
    msgs = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert msgs["1501"]["service"] == "police"
    c.post(f"/config/keyword/{kw['id']}/service", data={"csrf": token, "service": "<b>"})
    assert conn.execute("SELECT service FROM keywords WHERE id=?", (kw["id"],)).fetchone()[0] == ""
    # personal keyword service wins for that user only
    v = TestClient(app)
    login(v, "viewer1", "a brand new password")
    vt = csrf_of(v.get("/my").text)
    v.post("/my/keyword", data={"csrf": vt, "keyword": "main st", "match": "word", "service": "ambulance"})
    uk = conn.execute("SELECT * FROM user_keywords WHERE keyword='main st'").fetchone()
    assert uk["service"] == "ambulance"
    assert f'/my/keyword/{uk["id"]}/service' in v.get("/my").text
    vm = {m["capcode"]: m for m in v.get("/api/messages").json()["messages"]}
    am = {m["capcode"]: m for m in c.get("/api/messages").json()["messages"]}
    assert vm["1501"]["service"] == "ambulance" and am["1501"]["service"] == "police"
    v.post(f"/my/keyword/{uk['id']}/service", data={"csrf": vt, "service": "police"})
    assert conn.execute("SELECT service FROM user_keywords WHERE id=?", (uk["id"],)).fetchone()[0] == "police"
    assert v.post(f"/config/keyword/{kw['id']}/service", data={"csrf": vt, "service": "fire"}).status_code == 403
    conn.close()


def test_pushover_settings_and_alerts(app, monkeypatch):
    import json as _json
    from tests.test_pushover import FakePushover, TOKEN, USER
    from app import pushover
    from app.decoder import Decoder
    from app.parser import parse_line
    fake = FakePushover()
    monkeypatch.setattr(pushover, "API_URL", fake.url)
    conn = db.connect()
    _reset_personal(conn)
    try:
        c = TestClient(app)
        login(c, "alex")
        token = csrf_of(c.get("/config").text)
        # bad key refused, nothing saved
        c.post("/config/pushover", data={"csrf": token, "pushover_token": "nope", "pushover_user": USER})
        assert db.get_setting(conn, "pushover_token") == ""
        # good keys saved; the page never shows them in full
        c.post("/config/pushover", data={"csrf": token, "pushover_token": TOKEN, "pushover_user": USER,
                                         "pushover_priority": "0", "public_url": "https://pager.example.com/"})
        assert db.get_setting(conn, "pushover_token") == TOKEN
        assert db.get_setting(conn, "public_url") == "https://pager.example.com"
        page = c.get("/config").text
        assert TOKEN not in page and USER not in page and TOKEN[-4:] in page
        # blank fields keep the saved keys; a test goes to Pushover
        c.post("/config/pushover", data={"csrf": token, "pushover_priority": "1", "public_url": "https://pager.example.com", "test": "1"})
        assert db.get_setting(conn, "pushover_user") == USER and len(fake.requests) == 1
        assert fake.requests[0]["token"] == TOKEN and "Test alert" in fake.requests[0]["message"]
        # an alert page goes out through the decoder
        conn.execute("INSERT INTO aliases (capcode, label, alert, service) VALUES ('1500', 'Station 41', 1, 'fire')")
        d = Decoder.__new__(Decoder)
        d.conn, d.loc_cfg, d.loc_worker, d.dedupe_seconds, d.recent = conn, {}, None, 0, {}
        d.load_rules()
        d.push_sender = pushover.Sender(retry_wait=0.05)
        d.push_sender.start()
        ch = {"id": 1, "name": "Bench", "freq_hz": 157450000}
        d.store(ch, parse_line("POCSAG1200: Address: 1500  Function: 3  Alpha:   SMOKE ALARM"), time.time())
        d.store(ch, parse_line("POCSAG1200: Address: 5555  Function: 3  Alpha:   not an alert"), time.time())
        for _ in range(100):
            if len(fake.requests) >= 2:
                break
            time.sleep(0.02)
        sent = fake.requests[1]
        assert sent["title"].endswith("Station 41 · Bench") and sent["message"] == "SMOKE ALARM"
        assert sent["priority"] == 1 and sent["url"] == "https://pager.example.com/history?capcode=1500"
        time.sleep(0.2)
        assert len(fake.requests) == 2          # the non-alert page sent nothing
        # personal: a viewer with only a user key uses the shared app token, for pages they may see
        v = TestClient(app)
        login(v, "viewer1", "a brand new password")
        vt = csrf_of(v.get("/my/kiosks").text)
        assert "only need your" in v.get("/my/kiosks").text
        vuser = "v" * 29 + "3"
        v.post("/my/pushover", data={"csrf": vt, "pushover_user": vuser})
        vid = conn.execute("SELECT id FROM users WHERE username='viewer1'").fetchone()[0]
        assert conn.execute("SELECT pushover_user FROM users WHERE id=?", (vid,)).fetchone()[0] == vuser
        conn.execute("INSERT INTO user_keywords (user_id, keyword, alert) VALUES (?, 'boiler', 1)", (vid,))
        d.load_rules()
        fake.requests.clear()
        d.store(ch, parse_line("POCSAG1200: Address: 1501  Function: 3  Alpha:   BOILER fault"), time.time())
        d.store(ch, parse_line("POCSAG1200: Address: 9999  Function: 3  Alpha:   boiler outside filter"), time.time())
        time.sleep(0.4)
        assert [(r["user"], r["token"]) for r in fake.requests] == [(vuser, TOKEN)]
        # turning off clears it; removing shared keys stops shared alerts
        v.post("/my/pushover", data={"csrf": vt, "clear": "1"})
        assert conn.execute("SELECT pushover_user FROM users WHERE id=?", (vid,)).fetchone()[0] == ""
        c.post("/config/pushover", data={"csrf": token, "clear": "1"})
        assert db.get_setting(conn, "pushover_token") == "" and db.get_setting(conn, "pushover_user") == ""
        d.push_sender.stop()
    finally:
        fake.close()
        conn.execute("DELETE FROM aliases WHERE capcode = '1500'")
        conn.execute("UPDATE users SET pushover_user = '', pushover_token = ''")
        for k in ("pushover_token", "pushover_user", "public_url"):
            db.set_setting(conn, k, "")
        conn.close()


def test_pushover_send_modes_personal_and_debug_lines(app, monkeypatch):
    import queue as _q
    from tests.test_pushover import FakePushover, TOKEN, USER
    from app import pushover
    from app.decoder import Decoder
    from app.parser import parse_line
    fake = FakePushover()
    monkeypatch.setattr(pushover, "API_URL", fake.url)
    conn = db.connect()
    _reset_personal(conn)
    vid = conn.execute("SELECT id FROM users WHERE username='viewer1'").fetchone()[0]
    vkey = "v" * 29 + "4"

    def run(lines, wait_for):
        fake.requests.clear()
        for ln in lines:
            d.store(ch, parse_line(ln), time.time())
        for _ in range(150):
            if len(fake.requests) >= wait_for:
                break
            time.sleep(0.02)
        time.sleep(0.15)
        return list(fake.requests)
    try:
        for k, v in (("pushover_token", TOKEN), ("pushover_user", USER), ("pushover_send", "alerts"),
                     ("pushover_priority", "1")):
            db.set_setting(conn, k, v)
        conn.execute("INSERT INTO aliases (capcode, label, alert) VALUES ('1500', 'Station 41', 1)")
        conn.execute("INSERT INTO aliases (capcode, label, suppress) VALUES ('5555', 'Noisy', 1)")
        conn.execute("UPDATE users SET pushover_user = ? WHERE id = ?", (vkey, vid))
        d = Decoder.__new__(Decoder)
        d.conn, d.loc_cfg, d.loc_worker, d.dedupe_seconds, d.recent = conn, {}, None, 0, {}
        d.debug = _q.Queue()
        d.load_rules()
        ch = {"id": 1, "name": "Bench", "freq_hz": 157450000}
        status = [r[5] for r in list(d.debug.queue) if "Pushover ready" in r[5]]
        assert status and "alert pages only" in status[0] and "viewer1" in status[0]
        # alerts mode: the shared alert goes to the shared key AND to viewer1 (1500 is in their filter)
        sent = run(["POCSAG1200: Address: 1500  Function: 3  Alpha:   SMOKE ALARM",
                    "POCSAG1200: Address: 1600  Function: 3  Alpha:   routine page"], 2)
        assert sorted(r["user"] for r in sent) == sorted([USER, vkey]) and all(r["priority"] == 1 for r in sent)
        # the same key on both shared and personal gets one notification, not two
        conn.execute("UPDATE users SET pushover_user = ? WHERE id = ?", (USER, vid))
        d.load_rules()
        sent = run(["POCSAG1200: Address: 1500  Function: 3  Alpha:   SMOKE ALARM 2"], 1)
        assert [r["user"] for r in sent] == [USER]
        conn.execute("UPDATE users SET pushover_user = ? WHERE id = ?", (vkey, vid))
        # all-pages mode: ordinary pages go at Normal priority; suppressed and out-of-filter pages don't
        db.set_setting(conn, "pushover_send", "all")
        d.load_rules()
        sent = run(["POCSAG1200: Address: 1600  Function: 3  Alpha:   routine page",
                    "POCSAG1200: Address: 5555  Function: 3  Alpha:   noisy suppressed",
                    "POCSAG1200: Address: 9999  Function: 3  Alpha:   outside viewer filter"], 4)
        got = sorted((r["user"], r["message"][:7], r["priority"]) for r in sent)
        assert got == sorted([(USER, "routine", 0), (vkey, "routine", 0), (USER, "outside", 0)])
        # the Debug console gets a line per notification, and failures say why
        fake.replies.append((400, {"status": 0, "errors": ["application token is invalid"]}))
        run(["POCSAG1200: Address: 1700  Function: 3  Alpha:   last one"], 2)
        time.sleep(0.2)
        lines = [r for r in list(d.debug.queue)]
        texts = [r[5] for r in lines]
        assert any(t.startswith("Pushover to shared: sent") for t in texts)
        assert any(t.startswith("Pushover to viewer1: sent") for t in texts)
        bad = [r for r in lines if "failed: application token is invalid" in r[5]]
        assert bad and bad[0][4] == "error" and bad[0][2] == "Bench"
        assert not any(TOKEN in t or USER in t or vkey in t for t in texts)   # keys never logged
        d.push_sender.stop()
    finally:
        fake.close()
        conn.execute("DELETE FROM aliases WHERE capcode IN ('1500', '5555')")
        conn.execute("UPDATE users SET pushover_user = '', pushover_token = ''")
        for k in ("pushover_token", "pushover_user", "public_url"):
            db.set_setting(conn, k, "")
        db.set_setting(conn, "pushover_send", "alerts")
        conn.close()


def test_location_countries_setting(app):
    c = TestClient(app)
    login(c, "alex")
    token = csrf_of(c.get("/config").text)
    base = {"csrf": token, "loc_geocoder": "https://nominatim.openstreetmap.org/search",
            "map_tiles": "https://tile.openstreetmap.org/{z}/{x}/{y}.png"}
    conn = db.connect()
    try:
        c.post("/config/locations", data=dict(base, loc_countries="nz, au"))
        assert db.get_setting(conn, "loc_countries") == "nz,au"
        page = c.get("/config").text
        assert "New Zealand and Australia" in page
        c.post("/config/locations", data=dict(base, loc_countries="new zealand"))   # not codes: refused
        assert db.get_setting(conn, "loc_countries") == "nz,au"
        c.post("/config/locations", data=dict(base, loc_countries="nz, fj"))
        assert "can&#39;t be checked for Fiji" in c.get("/config").text or "can't be checked for Fiji" in c.get("/config").text
        c.post("/config/locations", data=dict(base, loc_countries=""))              # blank → New Zealand
        assert db.get_setting(conn, "loc_countries") == "nz"
    finally:
        db.set_setting(conn, "loc_countries", "nz")
        conn.close()
