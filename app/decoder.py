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
from .parser import Page, parse_line

log = logging.getLogger("pager.decoder")

SAMPLE_RATE = 22050  # what multimon-ng expects for raw input
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

    def __init__(self, channel: dict, out: queue.Queue, status: queue.Queue):
        super().__init__(name=f"channel-{channel['id']}", daemon=True)
        self.ch = channel
        self.out = out
        self.status = status
        self.stop_event = threading.Event()
        self.procs: list[subprocess.Popen] = []
        self.stderr_tail: deque[str] = deque(maxlen=5)

    def stop(self) -> None:
        self.stop_event.set()
        self._kill()

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
            finally:
                self._kill()
            if self.stop_event.is_set():
                break
            # A pipeline that ran for a while gets a fresh, short backoff.
            backoff = 2.0 if time.time() - started > 60 else min(backoff * 2, 60)
            tail = " | ".join(self.stderr_tail)
            self._set_status("restarting", f"retry in {int(backoff)}s. {tail}".strip())
            self.stop_event.wait(backoff)
        self._set_status("stopped")

    def _run_pipeline(self) -> None:
        rtl_cmd, mm_cmd = build_commands(self.ch)
        log.info("starting %s: %s | %s", self.ch["name"],
                 shlex.join(rtl_cmd), shlex.join(mm_cmd))
        rtl = subprocess.Popen(
            rtl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.procs.append(rtl)
        mm = subprocess.Popen(
            mm_cmd, stdin=rtl.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, errors="replace",
            bufsize=1, start_new_session=True,
        )
        self.procs.append(mm)
        rtl.stdout.close()  # multimon-ng owns the read end now

        threading.Thread(
            target=self._drain_stderr, args=(rtl,), daemon=True
        ).start()
        self._set_status("running", f"{self.ch['freq_hz'] / 1e6:.4f} MHz")

        for line in mm.stdout:
            if self.stop_event.is_set():
                break
            self._on_line(line)

        rc_rtl = rtl.poll()
        if not self.stop_event.is_set():
            log.warning("%s pipeline ended (rtl_fm rc=%s)", self.ch["name"], rc_rtl)

    def _drain_stderr(self, proc: subprocess.Popen) -> None:
        for raw in proc.stderr:
            text = raw.decode("utf-8", "replace").strip()
            if text:
                self.stderr_tail.append(text)
                log.debug("[%s rtl_fm] %s", self.ch["name"], text)

    def _run_simulated(self) -> None:
        self._set_status("running", f"SIMULATED from {settings.SIMULATE_FILE}")
        with open(settings.SIMULATE_FILE, encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]
        while not self.stop_event.is_set():
            for line in lines:
                if self.stop_event.wait(settings.SIMULATE_INTERVAL):
                    return
                self._on_line(line)

    def _on_line(self, line: str) -> None:
        page = parse_line(line)
        if page:
            self.out.put((self.ch, page, time.time()))


class Decoder:
    def __init__(self) -> None:
        db.init_db()
        self.conn = db.connect()
        self.pages: queue.Queue = queue.Queue()
        self.status: queue.Queue = queue.Queue()
        self.runners: dict[int, ChannelRunner] = {}
        self.config_version = ""
        self.aliases: dict[str, dict] = {}
        self.dedupe_seconds = 0
        self.webhook_url = ""
        self.recent: dict[tuple[str, str], float] = {}
        self.running = True
        self.last_purge = 0.0

    # --- configuration -------------------------------------------------
    def load_config(self) -> None:
        self.config_version = db.get_setting(self.conn, "config_version")
        self.dedupe_seconds = int(db.get_setting(self.conn, "dedupe_seconds", "0") or 0)
        self.webhook_url = db.get_setting(self.conn, "webhook_url").strip()
        self.aliases = {
            r["capcode"]: dict(r)
            for r in self.conn.execute("SELECT * FROM aliases")
        }
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
            runner = ChannelRunner(ch, self.pages, self.status)
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
        alias = self.aliases.get(page.capcode)
        if alias and alias["alert"] and self.webhook_url:
            payload = {
                "id": cur.lastrowid, "ts": ts, "channel": ch["name"],
                "freq_hz": ch["freq_hz"], "protocol": page.protocol,
                "capcode": page.capcode, "alias": alias["label"],
                "type": page.msg_type, "message": page.message,
            }
            threading.Thread(
                target=send_webhook, args=(self.webhook_url, payload), daemon=True
            ).start()

    def apply_status(self, channel_id: int, state: str, detail: str) -> None:
        self.conn.execute(
            "UPDATE channel_status SET state = ?, detail = ?, updated_at = ? "
            "WHERE channel_id = ?",
            (state, detail[:500], time.time(), channel_id),
        )

    def purge(self) -> None:
        days = int(db.get_setting(self.conn, "retention_days", "30") or 0)
        if days > 0:
            cutoff = time.time() - days * 86400
            n = self.conn.execute("DELETE FROM messages WHERE ts < ?", (cutoff,)).rowcount
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

            now = time.time()
            if now - last_check >= 2:
                last_check = now
                db.set_setting(self.conn, "decoder_heartbeat", f"{now:.0f}")
                if db.get_setting(self.conn, "config_version") != self.config_version:
                    log.info("configuration changed, reloading")
                    self.load_config()
            if now - self.last_purge > 3600:
                self.purge()
        self.stop_runners()
        while not self.status.empty():
            self.apply_status(*self.status.get_nowait())
        db.set_setting(self.conn, "decoder_heartbeat", "0")
        log.info("decoder stopped")

    def _on_signal(self, signum, frame) -> None:
        self.running = False


def send_webhook(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "pager-monitor"},
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
