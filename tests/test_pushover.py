import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app import pushover

TOKEN = "a" * 29 + "1"
USER = "u" * 29 + "2"


class FakePushover:
    """A local stand-in for api.pushover.net that records requests."""

    def __init__(self):
        self.requests, self.replies = [], []
        fake = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append(body)
                code, payload = fake.replies.pop(0) if fake.replies else (200, {"status": 1})
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/1/messages.json"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake(monkeypatch):
    f = FakePushover()
    monkeypatch.setattr(pushover, "API_URL", f.url)
    yield f
    f.close()


def test_build_title_message_and_limits():
    page = {"ts": 1792209643.4, "channel": "Totara Bay VHF", "capcode": "2041100", "type": "alpha",
            "message": "STRUCTURE FIRE " + "X" * 2000}
    f = pushover.build(page, label="Totara Bay Fire", service="fire", keywords=["structure fire"],
                       priority="1", link="https://pager.example.com/history?capcode=2041100")
    assert f["title"] == "\U0001F525 Totara Bay Fire · Totara Bay VHF"
    assert len(f["message"]) == 1024 and f["message"].startswith("STRUCTURE FIRE")
    assert f["priority"] == 1 and f["timestamp"] == 1792209643
    assert f["url"].endswith("capcode=2041100") and f["url_title"]
    # no label → capcode; tone pages get a description; bad priority falls back to high
    t = pushover.build({"capcode": "3100502", "type": "tone", "message": ""}, priority="9")
    assert t["title"] == "3100502" and "tone page to 3100502" in t["message"] and t["priority"] == 1
    assert "url" not in t
    assert len(pushover.build({"capcode": "1", "message": "x"}, label="L" * 400)["title"]) == 250


def test_key_checks_and_mask():
    assert pushover.valid_key(TOKEN) and not pushover.valid_key("short") and not pushover.valid_key("a" * 29 + "!")
    assert pushover.mask(TOKEN).endswith(TOKEN[-4:]) and TOKEN[:10] not in pushover.mask(TOKEN)
    assert pushover.mask("") == ""


def test_send_success_and_errors(fake):
    ok, retry, _ = pushover.send(TOKEN, USER, {"message": "hi", "title": "t"})
    assert ok and fake.requests[0] == {"token": TOKEN, "user": USER, "message": "hi", "title": "t"}
    fake.replies.append((400, {"status": 0, "errors": ["user identifier is not a valid user, group, or subscribed user key"]}))
    ok, retry, detail = pushover.send(TOKEN, USER, {"message": "hi"})
    assert not ok and not retry and "not a valid user" in detail
    fake.replies.append((500, {}))
    ok, retry, _ = pushover.send(TOKEN, USER, {"message": "hi"})
    assert not ok and retry


def test_sender_retries_once_after_server_error(fake):
    fake.replies.append((503, {}))
    s = pushover.Sender(retry_wait=0.05)
    s.start()
    s.enqueue(TOKEN, USER, {"message": "page"}, "shared")
    for _ in range(100):
        if len(fake.requests) >= 2:
            break
        threading.Event().wait(0.02)
    s.stop()
    assert len(fake.requests) == 2
    # a 4xx is never retried
    fake.requests.clear()
    fake.replies.append((429, {"errors": ["monthly limit reached"]}))
    s2 = pushover.Sender(retry_wait=0.05)
    s2.start()
    s2.enqueue(TOKEN, USER, {"message": "page"})
    threading.Event().wait(0.3)
    s2.stop()
    assert len(fake.requests) == 1
