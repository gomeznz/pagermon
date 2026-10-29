"""Pushover notifications for alert pages.

Pushover wants form or JSON POSTs to /1/messages.json carrying the app token,
the user (or group) key and the message. Its rules, which this module keeps:
  * message up to 1024 characters, title up to 250, URL up to 512
  * no more than 2 connections at once (one sender thread here)
  * after a 5xx or network error wait at least 5 seconds before retrying
  * 4xx means the request is wrong (bad key, quota used up): don't retry
"""

import json
import logging
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger("pushover")

API_URL = os.environ.get("PAGER_PUSHOVER_API", "https://api.pushover.net/1/messages.json")
KEY_RE = re.compile(r"^[A-Za-z0-9]{30}$")
SERVICE_ICON = {"fire": "\U0001F525", "police": "\U0001F46E", "ambulance": "\U0001F691"}
PRIORITIES = {"-1": "Quiet (no sound)", "0": "Normal", "1": "High (bypasses quiet hours)"}


def valid_key(value: str) -> bool:
    return bool(KEY_RE.match(value or ""))


def mask(value: str) -> str:
    return ("•" * 6 + value[-4:]) if value else ""


def build(page: dict, *, label: str = "", service: str = "", keywords=(), priority: str = "1",
          link: str = "") -> dict:
    """The Pushover fields for one page (without token and user)."""
    who = label or page.get("capcode", "")
    title = (SERVICE_ICON.get(service, "") + " " + who).strip()
    if page.get("channel"):
        title += f" · {page['channel']}"
    text = page.get("message") or f"({page.get('type') or 'tone'} page to {page.get('capcode', '')})"
    if keywords:
        text += "\n\nMatched: " + ", ".join(keywords)
    out = {"title": title[:250], "message": text[:1024], "timestamp": int(page.get("ts") or time.time()),
           "priority": int(priority if priority in PRIORITIES else "1")}
    if link:
        out["url"] = link[:512]
        out["url_title"] = "Open in MultipagePlus"
    return out


def send(token: str, user: str, fields: dict, timeout: float = 10) -> tuple[bool, bool, str]:
    """One POST. Returns (ok, worth_retrying, detail)."""
    body = json.dumps({"token": token, "user": user, **fields}).encode()
    req = urllib.request.Request(API_URL, data=body, headers={
        "Content-Type": "application/json", "User-Agent": "multipage"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            return True, False, "sent"
    except urllib.error.HTTPError as exc:
        try:
            errs = json.loads(exc.read().decode() or "{}").get("errors") or []
        except Exception:  # not JSON
            errs = []
        detail = "; ".join(errs) or f"HTTP {exc.code}"
        return False, exc.code >= 500, detail[:200]
    except Exception as exc:  # network trouble
        return False, True, str(exc)[:200]


class Sender(threading.Thread):
    """Sends queued notifications one at a time, retrying once on server or network errors."""

    def __init__(self, retry_wait: float = 6.0):
        super().__init__(name="pushover", daemon=True)
        self.q: queue.Queue = queue.Queue(maxsize=500)
        self.retry_wait = retry_wait
        self.stopping = threading.Event()

    def enqueue(self, token: str, user: str, fields: dict, who: str = "shared") -> None:
        try:
            self.q.put_nowait((token, user, fields, who))
        except queue.Full:
            log.warning("pushover queue full; dropping a %s notification", who)

    def stop(self) -> None:
        self.stopping.set()
        self.q.put(None)

    def run(self) -> None:
        while not self.stopping.is_set():
            item = self.q.get()
            if item is None:
                break
            token, user, fields, who = item
            ok, retry, detail = send(token, user, fields)
            if not ok and retry:
                self.stopping.wait(self.retry_wait)
                ok, retry, detail = send(token, user, fields)
            if not ok:
                log.warning("pushover (%s) failed: %s", who, detail)
