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
    assert "cap-link" not in c.get("/history").text


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
