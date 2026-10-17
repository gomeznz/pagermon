"""SQLite storage shared by the decoder service and the web app.

Both processes open the same database file. WAL mode lets the web app read
while the decoder writes. The decoder notices configuration changes by
watching the ``config_version`` setting, which the web app bumps on save.
"""

import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from . import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash        TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    capcode_filter TEXT NOT NULL DEFAULT '',
    active         INTEGER NOT NULL DEFAULT 1,
    created_at     REAL NOT NULL,
    last_login     REAL
);

CREATE TABLE IF NOT EXISTS channels (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    freq_hz      INTEGER NOT NULL,
    device       TEXT NOT NULL DEFAULT '0',
    gain         TEXT NOT NULL DEFAULT 'auto',
    ppm          INTEGER NOT NULL DEFAULT 0,
    squelch      INTEGER NOT NULL DEFAULT 0,
    protocols    TEXT NOT NULL DEFAULT 'POCSAG512,POCSAG1200,POCSAG2400,FLEX',
    pocsag_mode  TEXT NOT NULL DEFAULT 'auto',
    extra_rtl    TEXT NOT NULL DEFAULT '',
    extra_mm     TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS aliases (
    id       INTEGER PRIMARY KEY,
    capcode  TEXT NOT NULL UNIQUE,
    label    TEXT NOT NULL,
    alert    INTEGER NOT NULL DEFAULT 0,
    suppress INTEGER NOT NULL DEFAULT 0,
    colour   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY,
    ts           REAL NOT NULL,
    channel_id   INTEGER,
    channel_name TEXT NOT NULL DEFAULT '',
    freq_hz      INTEGER,
    protocol     TEXT NOT NULL,
    capcode      TEXT NOT NULL,
    function     TEXT NOT NULL DEFAULT '',
    msg_type     TEXT NOT NULL DEFAULT '',
    message      TEXT NOT NULL DEFAULT '',
    raw          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_messages_ts ON messages (ts);
CREATE INDEX IF NOT EXISTS ix_messages_capcode ON messages (capcode);

CREATE TABLE IF NOT EXISTS channel_status (
    channel_id  INTEGER PRIMARY KEY,
    state       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    started_at  REAL,
    last_msg_at REAL,
    msg_count   INTEGER NOT NULL DEFAULT 0,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keywords (
    id       INTEGER PRIMARY KEY,
    keyword  TEXT NOT NULL UNIQUE COLLATE NOCASE,
    match    TEXT NOT NULL DEFAULT 'word' CHECK (match IN ('word', 'contains')),
    alert    INTEGER NOT NULL DEFAULT 0,
    suppress INTEGER NOT NULL DEFAULT 0,
    colour   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS debug_log (
    id           INTEGER PRIMARY KEY,
    ts           REAL NOT NULL,
    channel_id   INTEGER,
    channel_name TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    text         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY,
    ts       REAL NOT NULL,
    username TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit (ts);
"""

DEFAULT_SETTINGS = {
    "retention_days": "30",
    "dedupe_seconds": "0",
    "webhook_url": "",
    "config_version": "1",
    "decoder_heartbeat": "0",
}


def connect(path: Path | None = None) -> sqlite3.Connection:
    path = Path(path or settings.DB_PATH)
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def init_db(path: Path | None = None) -> None:
    path = Path(path or settings.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value)
            )
        # Per-install secret used to sign session cookies.
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('session_secret', ?)",
            (secrets.token_urlsafe(48),),
        )
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases from earlier versions up to the current schema."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(aliases)")}
    if "suppress" not in cols:
        conn.execute("ALTER TABLE aliases ADD COLUMN suppress INTEGER NOT NULL DEFAULT 0")
    if "colour" not in cols:
        conn.execute("ALTER TABLE aliases ADD COLUMN colour TEXT NOT NULL DEFAULT ''")


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def bump_config_version(conn: sqlite3.Connection) -> None:
    """Tell the decoder service to reload its configuration."""
    conn.execute(
        "UPDATE settings SET value = CAST(value AS INTEGER) + 1 WHERE key = 'config_version'"
    )


def audit(conn: sqlite3.Connection, username: str, action: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit (ts, username, action, detail) VALUES (?, ?, ?, ?)",
        (time.time(), username, action, detail),
    )
