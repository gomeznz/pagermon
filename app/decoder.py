"""Decoder service: runs rtl_fm | multimon-ng per channel and stores pages.

Run with:  python -m app.decoder

One RTL-SDR dongle receives one frequency in this version (rtl_fm's limit).
Add more channels by adding more dongles, each with its own device index or
serial number.

The service:
  * starts a pipeline per enabled channel and restarts it if it dies
  * parses decoded lines and writes them to SQLite
  * reloads all pipelines when the web UI saves a config change
  * sends webhook alerts for capcodes flagged in Aliases
  * purges messages older than the retention period
"""

import json
import logging
import os
import queue
import shlex
import shutil
import signal
import subprocess
import threading
import time
import urllib.request
from collections import deque

from . import db, settings
from . import auth, locations, pushover, rules as kwrules
from .parser import Page, parse_line

log = logging.getLogger("pager.decoder")

SAMPLE_RATE = 22050  # what multimon-ng expects for raw input
DEBUG_KEEP = 5000  # raw lines kept for the debug console
VALID_PROTOCOLS = ("POCSAG512", "POCSAG1200", "POCSAG2400", "FLEX", "FLEX_NEXT")


def build_commands(ch: dict) -> tuple[list[str], list[str]]:
    """Return (rtl_fm argv, multimon-ng argv) for a channel row."""
    rtl = [
        settings.RTL_FM,
        "-d", str(ch["device"]).strip() or "0",
        "-f", str(int(ch["freq_hz"])),
        "-M", "fm",
        "-s", str(SAMPLE_RATE),
        "-p", str(int(ch["ppm"])),
        "-l", str(int(ch["squelch"])),
        "-E", "dc",
    ]
    gain = str(ch["gain"]).strip().lower()
    if gain and gain != "auto":
        rtl += ["-g", gain]
    rtl += shlex.split(ch["extra_rtl"] or "")
    rtl.append("-")

    mm = [settings.MULTIMON, "-t", "raw"]
    stdbuf = shutil.which("stdbuf")
    if stdbuf:
        # Force line-buffered output so pages appear the moment they decode.
        mm = [stdbuf, "-oL"] + mm
    for proto in (p.strip() for p in ch["protocols"].split(",")):
        if proto in VALID_PROTOCOLS:
            mm += ["-a", proto]
    mode = (ch["pocsag_mode"] or "auto").strip().lower()
    if mode in ("alpha", "numeric", "skyper"):
        mm += ["-f", mode]
    mm += shlex.split(ch["extra_mm"] or "")
    mm.append("-")
    return rtl, mm


class ChannelRunner(threading.Thread):
    """Keeps one channel's receive pipeline running until stopped."""

    def __init__(self, channel: dict, out: queue.Queue, status: queue.Queue,
                 debug: queue.Queue | None = None):
        super().__init__(name=f"channel-{channel['id']}", daemon=True)
        self.ch = channel
        self.out = out
        self.status = status
        self.debug = debug
        self.stop_event = threading.Event()
        self.procs: list[subprocess.Popen] = []
        self.stderr_tail: deque[str] = deque(maxlen=5)

    def stop(self) -> None:
        self.stop_event.set()
        self._kill()

    def _debug(self, source: str, kind: str, text: str) -> None:
        """Record a raw line or event for the debug console."""
        if self.debug is not None:
            self.debug.put((time.time(), self.ch["id"], self.ch["name"], source, kind, text[:2000]))

    def _set_status(self, state: str, detail: str = "") -> None:
        self.status.put((self.ch["id"], state, detail))

    def _kill(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
        deadline = time.time() + 3
        for p in self.procs:
            try:
                p.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.procs = []

    def run(self) -> None:
        backoff = 2.0
        while not self.stop_event.is_set():
            started = time.time()
            try:
                if settings.SIMULATE_FILE:
                    self._run_simulated()
                else:
                    self._run_pipeline()
            except Exception as exc:  # keep the service alive no matter what
                log.exception("channel %s crashed", self.ch["name"])
                self._set_status("error", str(exc))
                self._debug("decoder", "error", f"pipeline error: {exc}")
            finally:
                self._kill()
            if self.stop_event.is_set():
                break
            # A pipeline that ran for a while gets a fresh, short backoff.
            backoff = 2.0 if time.time() - started > 60 else min(backoff * 2, 60)
            tail = " | ".join(self.stderr_tail)
            self._set_status("restarting", f"retry in {int(backoff)}s. {tail}".strip())
            self._debug("decoder", "error", f"pipeline stopped; restarting in {int(backoff)}s")
            self.stop_event.wait(backoff)
        self._set_status("stopped")

    def _run_pipeline(self) -> None:
        rtl_cmd, mm_cmd = build_commands(self.ch)
        log.info("starting %s: %s | %s", self.ch["name"],
                 shlex.join(rtl_cmd), shlex.join(mm_cmd))
        self._debug("decoder", "info", "start: " + shlex.join(rtl_cmd) + " | " + shlex.join(mm_cmd))
        rtl = subprocess.Popen(
            rtl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.procs.append(rtl)
        mm = subprocess.Popen(
            mm_cmd, stdin=rtl.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, errors="replace",
            bufsize=1, start_new_session=True,
        )
        self.procs.append(mm)
        rtl.stdout.close()  # multimon-ng owns the read end now

        threading.Thread(
            target=self._drain_stderr, args=(rtl, "rtl_fm"), daemon=True
        ).start()
        threading.Thread(
            target=self._drain_stderr, args=(mm, "multimon"), daemon=True
        ).start()
        self._set_status("running", f"{self.ch['freq_hz'] / 1e6:.4f} MHz")

        for line in mm.stdout:
            if self.stop_event.is_set():
                break
            self._on_line(line)

        rc_rtl = rtl.poll()
        if not self.stop_event.is_set():
            log.warning("%s pipeline ended (rtl_fm rc=%s)", self.ch["name"], rc_rtl)
            self._debug("decoder", "error",
                        f"multimon-ng output ended (rtl_fm exit={rc_rtl}, multimon-ng exit={mm.poll()})")

    def _drain_stderr(self, proc: subprocess.Popen, source: str) -> None:
        for raw in proc.stderr:
            text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
            text = text.strip()
            if text:
                if source == "rtl_fm":
                    self.stderr_tail.append(text)
                self._debug(source, "stderr", text)
                log.debug("[%s %s] %s", self.ch["name"], source, text)

    def _run_simulated(self) -> None:
        self._set_status("running", f"SIMULATED from {settings.SIMULATE_FILE}")
        self._debug("decoder", "info", f"simulation: replaying {settings.SIMULATE_FILE}")
        with open(settings.SIMULATE_FILE, encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]
        while not self.stop_event.is_set():
            for line in lines:
                if self.stop_event.wait(settings.SIMULATE_INTERVAL):
                    return
                self._on_line(line)

    def _on_line(self, line: str) -> None:
        page = parse_line(line)
        text = line.rstrip("\r\n")
        if text:
            # Every line multimon-ng prints, tagged with whether we could parse it.
            self._debug("multimon", "parsed" if page else "unparsed", text)
        if page:
            self.out.put((self.ch, page, time.time()))


class Decoder:
    def __init__(self) -> None:
        db.init_db()
        self.conn = db.connect()
        self.pages: queue.Queue = queue.Queue()
        self.status: queue.Queue = queue.Queue()
        self.debug: queue.Queue = queue.Queue()
        self.debug_since_prune = 0
        self.runners: dict[int, ChannelRunner] = {}
        self.config_version = ""
        self.aliases: dict[str, dict] = {}
        self.keyword_rules: list = []
        self.personal: list = []
        self.rules_version = ""
        self.loc_cfg: dict = {}
        self.loc_worker = None
        self.dedupe_seconds = 0
        self.webhook_url = ""
        self.push: dict = {}
        self.push_sender = None
        self.recent: dict[tuple[str, str], float] = {}
        self.running = True
        self.last_purge = 0.0

    # --- configuration -------------------------------------------------
    def load_rules(self) -> None:
        """Capcode/keyword rules and alert settings. Reloading these never touches the radio."""
        self.rules_version = db.get_setting(self.conn, "rules_version")
        self.dedupe_seconds = int(db.get_setting(self.conn, "dedupe_seconds", "0") or 0)
        self.webhook_url = db.get_setting(self.conn, "webhook_url").strip()
        self.aliases = {
            r["capcode"]: dict(r)
            for r in self.conn.execute("SELECT * FROM aliases")
        }
        self.keyword_rules = kwrules.load_rules(self.conn)
        # Location lookups: settings are shared with the worker thread, which has its own connection.
        cfg = {k: db.get_setting(self.conn, k, v) for k, v in locations.DEFAULTS.items()}
        if not hasattr(self, "loc_cfg"):
            self.loc_cfg, self.loc_worker = {}, None
        self.loc_cfg.clear()
        self.loc_cfg.update(cfg)
        if self.loc_cfg.get("loc_enabled") == "1" and self.loc_worker is None:
            self.loc_worker = locations.LocationWorker(db.connect, self.loc_cfg)
            self.loc_worker.start()
        # Users with their own alert webhook: (user row, their personal view, parsed filter)
        self.push = {k: db.get_setting(self.conn, k).strip() for k in
                     ("pushover_token", "pushover_user", "pushover_priority", "pushover_send", "public_url")}
        self.personal = []
        for u in self.conn.execute(
                "SELECT * FROM users WHERE active = 1 AND (notify_url != '' OR pushover_user != '')").fetchall():
            self.personal.append((dict(u), kwrules.load_view(self.conn, u["id"]),
                                  auth.parse_capcode_filter(u["capcode_filter"])))
        self._push_status()

    def load_config(self) -> None:
        self.config_version = db.get_setting(self.conn, "config_version")
        self.load_rules()
        channels = [
            dict(r) for r in self.conn.execute("SELECT * FROM channels WHERE enabled = 1")
        ]
        self.stop_runners()
        # Discard status updates from the runners just stopped so they don't
        # overwrite the rows for the new ones.
        while not self.status.empty():
            self.status.get_nowait()
        self.conn.execute("DELETE FROM channel_status")
        for ch in channels:
            runner = ChannelRunner(ch, self.pages, self.status, self.debug)
            self.runners[ch["id"]] = runner
            self.conn.execute(
                "INSERT INTO channel_status (channel_id, state, started_at, updated_at) "
                "VALUES (?, 'starting', ?, ?)",
                (ch["id"], time.time(), time.time()),
            )
            runner.start()
        log.info("config v%s loaded: %d channel(s)", self.config_version, len(channels))

    def stop_runners(self) -> None:
        for runner in self.runners.values():
            runner.stop()
        for runner in self.runners.values():
            runner.join(timeout=5)
        self.runners = {}

    # --- message handling ----------------------------------------------
    def store(self, ch: dict, page: Page, ts: float) -> None:
        if self.dedupe_seconds > 0:
            key = (page.capcode, page.message)
            last = self.recent.get(key)
            self.recent[key] = ts
            if last and ts - last < self.dedupe_seconds:
                return
            if len(self.recent) > 5000:
                cutoff = ts - self.dedupe_seconds
                self.recent = {k: v for k, v in self.recent.items() if v >= cutoff}

        cur = self.conn.execute(
            "INSERT INTO messages (ts, channel_id, channel_name, freq_hz, protocol, "
            "capcode, function, msg_type, message, raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ts, ch["id"], ch["name"], ch["freq_hz"], page.protocol, page.capcode,
             page.function, page.msg_type, page.message, page.raw),
        )
        self.conn.execute(
            "UPDATE channel_status SET msg_count = msg_count + 1, last_msg_at = ?, "
            "updated_at = ? WHERE channel_id = ?",
            (ts, ts, ch["id"]),
        )
        if (self.loc_worker and self.loc_cfg.get("loc_enabled") == "1"
                and page.msg_type in ("alpha", "other") and page.message):
            self.loc_worker.enqueue(cur.lastrowid, page.message)
        alias = self.aliases.get(page.capcode) or {}
        res = kwrules.evaluate(page.message, self.keyword_rules,
                               alias.get("alert", 0), alias.get("suppress", 0),
                               alias.get("colour", ""), alias.get("service", "") or "")
        if res.alert and self.webhook_url:
            payload = {
                "id": cur.lastrowid, "ts": ts, "channel": ch["name"],
                "freq_hz": ch["freq_hz"], "protocol": page.protocol,
                "capcode": page.capcode, "alias": alias.get("label", ""),
                "keywords": res.keywords, "service": res.service,
                "type": page.msg_type, "message": page.message,
            }
            threading.Thread(
                target=send_webhook, args=(self.webhook_url, payload), daemon=True
            ).start()
        page_info = {"ts": ts, "channel": ch["name"], "capcode": page.capcode,
                     "type": page.msg_type, "message": page.message}
        send_all = self.push.get("pushover_send") == "all"
        meta = (ch["id"], ch["name"])
        shared_key = self.push.get("pushover_user") if self.push.get("pushover_token") else ""
        shared_sent = False
        if shared_key and (res.alert or (send_all and not res.suppressed)):
            self.pushover(self.push["pushover_token"], shared_key, page_info, alias.get("label", ""),
                          res.service, res.keywords, "shared", res.alert, meta)
            shared_sent = True
        # Personal alerts go to each user's own webhook, only for pages they may see.
        for u, view, ranges in self.personal:
            if not auth.capcode_matches(ranges, page.capcode):
                continue
            shown = kwrules.apply_view(page.message, page.capcode, view, alias.get("alert", 0),
                                       alias.get("suppress", 0), alias.get("colour", ""),
                                       alias.get("label", ""), alias.get("service", "") or "")
            # Personal Pushover: pages that alert for this user (shared alerts they can see,
            # plus their own Alert me), or every page they can see in "all pages" mode.
            token = u.get("pushover_token") or self.push.get("pushover_token")
            if (u.get("pushover_user") and token and (shown.alert or (send_all and not shown.suppressed))
                    and not (shared_sent and u["pushover_user"] == shared_key)):
                self.pushover(token, u["pushover_user"], page_info, shown.label, shown.service,
                              shown.keywords, u["username"], shown.alert, meta)
            # Personal webhooks keep to the user's own Alert me rules.
            if shown.personal_alert:
                payload = {
                    "id": cur.lastrowid, "ts": ts, "channel": ch["name"], "user": u["username"],
                    "protocol": page.protocol, "capcode": page.capcode, "alias": shown.label,
                    "keywords": shown.keywords, "service": shown.service, "type": page.msg_type, "message": page.message,
                }
                if u.get("notify_url"):
                    threading.Thread(target=send_webhook, args=(u["notify_url"], payload), daemon=True).start()

    def pushover(self, token: str, user: str, page_info: dict, label: str, service: str,
                 keywords, who: str, is_alert: bool = True, meta=None) -> None:
        if getattr(self, "push_sender", None) is None:
            self.push_sender = pushover.Sender(report=self._push_report)
            self.push_sender.start()
        base = self.push.get("public_url", "").rstrip("/")
        link = f"{base}/history?capcode={page_info['capcode']}" if base else ""
        prio = pushover.priority_for(self.push.get("pushover_priority", "1"), is_alert)
        fields = pushover.build(page_info, label=label, service=service, keywords=keywords,
                                priority=prio, link=link)
        self.push_sender.enqueue(token, user, fields, who, meta)

    def _debug_event(self, kind: str, text: str, meta=None) -> None:
        """Add a line to the Debug console (shown as an event)."""
        q = getattr(self, "debug", None)
        if q is not None:
            cid, cname = meta or (None, "")
            q.put((time.time(), cid, cname, "decoder", kind, text[:2000]))

    def _push_report(self, ok: bool, who: str, fields: dict, detail: str, meta) -> None:
        title = fields.get("title", "")
        if ok:
            self._debug_event("info", f"Pushover to {who}: sent \u201c{title}\u201d", meta)
        else:
            self._debug_event("error", f"Pushover to {who} failed: {detail} (\u201c{title}\u201d)", meta)

    def _push_status(self) -> None:
        """Say in the Debug console what Pushover will do, whenever settings or rules reload."""
        mode = pushover.SEND_MODES.get(self.push.get("pushover_send") or "alerts", "Alert pages only").lower()
        shared = bool(self.push.get("pushover_token") and self.push.get("pushover_user"))
        people = [u["username"] for u, _, _ in self.personal
                  if u.get("pushover_user") and (u.get("pushover_token") or self.push.get("pushover_token"))]
        if not shared and not people:
            return
        n_alert = self.conn.execute("SELECT COUNT(*) FROM aliases WHERE alert = 1 AND suppress = 0").fetchone()[0] \
            + self.conn.execute("SELECT COUNT(*) FROM keywords WHERE alert = 1").fetchone()[0]
        parts = [f"Pushover ready: {mode}"]
        parts.append("shared on" if shared else "shared off")
        if people:
            parts.append("personal: " + ", ".join(people))
        if (self.push.get("pushover_send") or "alerts") == "alerts":
            parts.append(f"{n_alert} shared capcode/keyword rule{'s' if n_alert != 1 else ''} with Alert ticked")
        self._debug_event("info" if (n_alert or people or self.push.get("pushover_send") == "all") else "error",
                          "; ".join(parts))

    def apply_status(self, channel_id: int, state: str, detail: str) -> None:
        self.conn.execute(
            "UPDATE channel_status SET state = ?, detail = ?, updated_at = ? "
            "WHERE channel_id = ?",
            (state, detail[:500], time.time(), channel_id),
        )

    def store_debug(self) -> None:
        rows = []
        while len(rows) < 1000:
            try:
                rows.append(self.debug.get_nowait())
            except queue.Empty:
                break
        if not rows:
            return
        self.conn.executemany(
            "INSERT INTO debug_log (ts, channel_id, channel_name, source, kind, text) "
            "VALUES (?, ?, ?, ?, ?, ?)", rows)
        self.debug_since_prune += len(rows)
        if self.debug_since_prune >= 500:
            self.debug_since_prune = 0
            self.conn.execute(
                "DELETE FROM debug_log WHERE id <= (SELECT MAX(id) FROM debug_log) - ?",
                (DEBUG_KEEP,))

    def purge(self) -> None:
        days = int(db.get_setting(self.conn, "retention_days", "30") or 0)
        if days > 0:
            cutoff = time.time() - days * 86400
            n = self.conn.execute("DELETE FROM messages WHERE ts < ?", (cutoff,)).rowcount
            self.conn.execute("DELETE FROM message_locations WHERE message_id NOT IN (SELECT id FROM messages)")
            self.conn.execute("DELETE FROM geocode_cache WHERE ts < ?", (time.time() - 90 * 86400,))
            self.conn.execute("DELETE FROM audit WHERE ts < ?", (time.time() - 365 * 86400,))
            if n:
                log.info("retention: purged %d message(s) older than %d days", n, days)
        self.last_purge = time.time()

    # --- main loop -----------------------------------------------------
    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        self.load_config()
        last_check = 0.0
        while self.running:
            try:
                ch, page, ts = self.pages.get(timeout=0.5)
                self.store(ch, page, ts)
                while True:  # drain any burst in one go
                    ch, page, ts = self.pages.get_nowait()
                    self.store(ch, page, ts)
            except queue.Empty:
                pass
            while not self.status.empty():
                self.apply_status(*self.status.get_nowait())
            self.store_debug()

            now = time.time()
            if now - last_check >= 2:
                last_check = now
                db.set_setting(self.conn, "decoder_heartbeat", f"{now:.0f}")
                if db.get_setting(self.conn, "config_version") != self.config_version:
                    log.info("channel configuration changed, restarting receivers")
                    self.load_config()
                elif db.get_setting(self.conn, "rules_version") != self.rules_version:
                    log.info("rules changed, reloading (receivers keep running)")
                    self.load_rules()
            if now - self.last_purge > 3600:
                self.purge()
        self.stop_runners()
        while not self.status.empty():
            self.apply_status(*self.status.get_nowait())
        self.store_debug()
        db.set_setting(self.conn, "decoder_heartbeat", "0")
        log.info("decoder stopped")

    def _on_signal(self, signum, frame) -> None:
        self.running = False


def send_webhook(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "multipage"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as exc:
        log.warning("webhook failed: %s", exc)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("PAGER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    Decoder().run()


if __name__ == "__main__":
    main()
