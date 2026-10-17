"""Web front end: live feed, history, configuration and user management.

Run with:  python -m app.web
"""

import asyncio
import csv
import io
import re
import secrets
import shlex
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (
    HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, auth, db, settings
from .decoder import VALID_PROTOCOLS

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=BASE / "templates")
limiter = auth.LoginLimiter()

PAGE_SIZE = 100
ALLOWED_ARG_RE = re.compile(r"^[A-Za-z0-9 .:=_+,/-]*$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


# --- helpers ------------------------------------------------------------

class LoginRequired(Exception):
    pass


class AdminRequired(Exception):
    pass


def fmt_ts(ts) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


def fmt_mhz(hz) -> str:
    return f"{int(hz) / 1e6:.4f}" if hz else ""


templates.env.filters["ts"] = fmt_ts
templates.env.filters["mhz"] = fmt_mhz


def pw_tag(pw_hash: str) -> str:
    """Short fingerprint of the password hash, kept in the session so that a
    password change or reset logs out every other session for that user."""
    return pw_hash[-12:]


def client_ip(request: Request) -> str:
    if settings.TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def load_user(conn, session) -> dict | None:
    uid = session.get("uid")
    if not uid:
        return None
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row or not row["active"] or session.get("pw") != pw_tag(row["pw_hash"]):
        return None
    if time.time() - session.get("t", 0) > settings.SESSION_HOURS * 3600:
        return None
    return dict(row)


def require_user(request: Request, admin: bool = False) -> tuple:
    conn = db.connect()
    user = load_user(conn, request.session)
    if not user:
        conn.close()
        request.session.clear()
        raise LoginRequired()
    if admin and user["role"] != "admin":
        conn.close()
        raise AdminRequired()
    return conn, user


def check_csrf(request: Request, token: str) -> None:
    expected = request.session.get("csrf", "")
    if not expected or not secrets.compare_digest(expected, token or ""):
        raise AdminRequired()


def flash(request: Request, message: str, kind: str = "ok") -> None:
    request.session.setdefault("flash", []).append([kind, message])


def render(request: Request, name: str, user: dict | None, **ctx) -> HTMLResponse:
    messages = request.session.pop("flash", [])
    return templates.TemplateResponse(
        request, name,
        {"user": user, "csrf": request.session.get("csrf", ""), "flashes": messages,
         "version": __version__, **ctx},
    )


def back(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def message_query(user: dict, f: dict) -> tuple[str, list]:
    """WHERE clause for message searches, always including the user's filter."""
    where, params = auth.capcode_sql(user["capcode_filter"])
    clauses, args = [where], list(params)
    if f.get("q"):
        clauses.append("m.message LIKE ? ESCAPE '\\'")
        q = f["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        args.append(f"%{q}%")
    if f.get("capcode"):
        cf = auth.parse_capcode_filter(f["capcode"])
        if cf:
            c_sql, c_args = auth.capcode_sql(f["capcode"])
            clauses.append(c_sql)
            args += c_args
    if f.get("protocol"):
        clauses.append("m.protocol LIKE ?")
        args.append(f["protocol"] + "%")
    if f.get("channel"):
        clauses.append("m.channel_id = ?")
        args.append(int(f["channel"]))
    for key, op in (("start", ">="), ("end", "<=")):
        if f.get(key):
            try:
                ts = datetime.fromisoformat(f[key]).timestamp()
                clauses.append(f"m.ts {op} ?")
                args.append(ts)
            except ValueError:
                pass
    return " AND ".join(clauses), args


MSG_SELECT = (
    "SELECT m.*, a.label AS alias FROM messages m "
    "LEFT JOIN aliases a ON a.capcode = m.capcode "
)


def msg_dict(row) -> dict:
    d = dict(row)
    d.pop("raw", None)
    d["time"] = fmt_ts(d["ts"])
    return d


# --- app ----------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


def create_app() -> FastAPI:
    db.init_db()
    conn = db.connect()
    secret = db.get_setting(conn, "session_secret")
    conn.close()

    app = FastAPI(title="MultipagePlus", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware, secret_key=secret, session_cookie="pm_session",
        max_age=settings.SESSION_HOURS * 3600, same_site="strict",
        https_only=settings.SECURE_COOKIES,
    )
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'none'"
        )
        if request.url.path not in ("/healthz",) and not request.url.path.startswith("/static"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "login required"}, status_code=401)
        nxt = request.url.path if request.method == "GET" else "/"
        return back("/login?next=" + quote(nxt))

    @app.exception_handler(AdminRequired)
    async def _forbidden(request: Request, exc):
        return PlainTextResponse("Forbidden", status_code=403)

    # --- auth ------------------------------------------------------------

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request, next: str = "/"):
        request.session.setdefault("csrf", secrets.token_urlsafe(32))
        return render(request, "login.html", None, next=_safe_next(next))

    @app.post("/login")
    async def login(request: Request, username: str = Form(""), password: str = Form(""),
                    next: str = Form("/"), csrf: str = Form("")):
        check_csrf(request, csrf)
        username = username.strip()
        ip = client_ip(request)
        keys = (f"u:{username.lower()}", f"ip:{ip}")
        conn = db.connect()
        try:
            if limiter.blocked(*keys):
                db.audit(conn, username or "?", "login_blocked", ip)
                flash(request, "Too many failed attempts. Try again in 15 minutes.", "error")
                return back("/login")
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            ok = await asyncio.to_thread(auth.check_login, row, password)
            if not ok:
                limiter.fail(*keys)
                db.audit(conn, username or "?", "login_failed", ip)
                flash(request, "Incorrect username or password.", "error")
                return back("/login?next=" + quote(_safe_next(next)))
            limiter.clear(*keys)
            request.session.clear()
            request.session.update({
                "uid": row["id"], "pw": pw_tag(row["pw_hash"]), "t": time.time(),
                "csrf": secrets.token_urlsafe(32),
            })
            conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), row["id"]))
            db.audit(conn, row["username"], "login", ip)
            return back(_safe_next(next))
        finally:
            conn.close()

    @app.post("/logout")
    async def logout(request: Request, csrf: str = Form("")):
        check_csrf(request, csrf)
        request.session.clear()
        return back("/login")

    # --- live and history -------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def live(request: Request):
        conn, user = require_user(request)
        try:
            channels = conn.execute("SELECT id, name FROM channels ORDER BY name").fetchall()
            return render(request, "live.html", user, channels=channels, page_name="live")
        finally:
            conn.close()

    @app.get("/api/messages")
    async def api_messages(request: Request, after: int = 0, limit: int = 50):
        conn, user = require_user(request)
        try:
            where, args = message_query(user, {})
            limit = max(1, min(limit, 500))
            if after:
                rows = conn.execute(
                    MSG_SELECT + f"WHERE {where} AND m.id > ? ORDER BY m.id ASC LIMIT ?",
                    args + [after, limit]).fetchall()
            else:
                rows = conn.execute(
                    MSG_SELECT + f"WHERE {where} ORDER BY m.id DESC LIMIT ?",
                    args + [limit]).fetchall()[::-1]
            return {"messages": [msg_dict(r) for r in rows]}
        finally:
            conn.close()

    @app.get("/api/status")
    async def api_status(request: Request):
        conn, user = require_user(request)
        try:
            return status_payload(conn)
        finally:
            conn.close()

    @app.websocket("/ws")
    async def ws_feed(websocket: WebSocket):
        # Refuse cross-site connections: the browser always sends Origin.
        origin = websocket.headers.get("origin", "")
        host = websocket.headers.get("host", "")
        if not origin or origin.split("://", 1)[-1] != host:
            await websocket.close(code=1008)
            return
        conn = db.connect()
        user = load_user(conn, websocket.session)
        if not user:
            conn.close()
            await websocket.close(code=1008)
            return
        await websocket.accept()
        where, args = message_query(user, {})
        try:
            rows = conn.execute(
                MSG_SELECT + f"WHERE {where} ORDER BY m.id DESC LIMIT 100", args
            ).fetchall()[::-1]
            last_id = rows[-1]["id"] if rows else (
                conn.execute("SELECT COALESCE(MAX(id), 0) FROM messages").fetchone()[0])
            await websocket.send_json({"type": "messages", "messages": [msg_dict(r) for r in rows]})
            await websocket.send_json({"type": "status", **status_payload(conn)})
            ticks = 0
            while True:
                await asyncio.sleep(1)
                ticks += 1
                # Re-check the session so a disabled user or reset password
                # cuts off an open live feed too.
                if ticks % 10 == 0 and not load_user(conn, websocket.session):
                    await websocket.close(code=1008)
                    return
                rows = conn.execute(
                    MSG_SELECT + f"WHERE {where} AND m.id > ? ORDER BY m.id ASC LIMIT 200",
                    args + [last_id]).fetchall()
                newest = conn.execute("SELECT COALESCE(MAX(id), 0) FROM messages").fetchone()[0]
                if rows:
                    await websocket.send_json(
                        {"type": "messages", "messages": [msg_dict(r) for r in rows]})
                last_id = max(last_id, newest)
                if ticks % 5 == 0:
                    await websocket.send_json({"type": "status", **status_payload(conn)})
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            conn.close()

    @app.get("/history", response_class=HTMLResponse)
    async def history(request: Request, q: str = "", capcode: str = "", protocol: str = "",
                      channel: str = "", start: str = "", end: str = "", page: int = 1):
        conn, user = require_user(request)
        try:
            f = {"q": q.strip(), "capcode": capcode.strip(), "protocol": protocol,
                 "channel": channel if channel.isdigit() else "", "start": start, "end": end}
            where, args = message_query(user, f)
            page = max(1, page)
            total = conn.execute(f"SELECT COUNT(*) FROM messages m WHERE {where}", args).fetchone()[0]
            rows = conn.execute(
                MSG_SELECT + f"WHERE {where} ORDER BY m.id DESC LIMIT ? OFFSET ?",
                args + [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
            channels = conn.execute("SELECT id, name FROM channels ORDER BY name").fetchall()
            pages = max(1, -(-total // PAGE_SIZE))
            qs = urlencode({k: v for k, v in f.items() if v})
            return render(request, "history.html", user, rows=rows, f=f, total=total,
                          page=page, pages=pages, qs=qs, channels=channels, page_name="history")
        finally:
            conn.close()

    @app.get("/history.csv")
    async def history_csv(request: Request, q: str = "", capcode: str = "", protocol: str = "",
                          channel: str = "", start: str = "", end: str = ""):
        conn, user = require_user(request)
        f = {"q": q.strip(), "capcode": capcode.strip(), "protocol": protocol,
             "channel": channel if channel.isdigit() else "", "start": start, "end": end}
        where, args = message_query(user, f)
        rows = conn.execute(MSG_SELECT + f"WHERE {where} ORDER BY m.id DESC LIMIT 100000",
                            args).fetchall()
        db.audit(conn, user["username"], "export_csv", f"{len(rows)} rows")
        conn.close()

        def generate():
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["time", "channel", "freq_mhz", "protocol", "capcode", "alias",
                        "function", "type", "message"])
            for r in rows:
                w.writerow([fmt_ts(r["ts"]), r["channel_name"], fmt_mhz(r["freq_hz"]),
                            r["protocol"], r["capcode"], r["alias"] or "", r["function"],
                            r["msg_type"], _csv_safe(r["message"])])
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()

        name = f"pages-{datetime.now():%Y%m%d-%H%M}.csv"
        return StreamingResponse(generate(), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{name}"'})

    # --- configuration (admin) --------------------------------------------

    @app.get("/config", response_class=HTMLResponse)
    async def config(request: Request, edit: int = 0):
        conn, user = require_user(request, admin=True)
        try:
            channels = conn.execute("SELECT * FROM channels ORDER BY name").fetchall()
            editing = None
            if edit:
                editing = conn.execute("SELECT * FROM channels WHERE id = ?", (edit,)).fetchone()
            aliases = conn.execute("SELECT * FROM aliases ORDER BY CAST(capcode AS INTEGER)").fetchall()
            s = {k: db.get_setting(conn, k) for k in ("retention_days", "dedupe_seconds", "webhook_url")}
            return render(request, "config.html", user, channels=channels, editing=editing,
                          aliases=aliases, s=s, protocols=VALID_PROTOCOLS, page_name="config")
        finally:
            conn.close()

    @app.post("/config/channel")
    async def save_channel(request: Request, csrf: str = Form(""), id: int = Form(0),
                           name: str = Form(""), freq_mhz: str = Form(""), device: str = Form("0"),
                           gain: str = Form("auto"), ppm: str = Form("0"), squelch: str = Form("0"),
                           protocols: list[str] = Form([]), pocsag_mode: str = Form("auto"),
                           extra_rtl: str = Form(""), extra_mm: str = Form(""),
                           enabled: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            errors = []
            name = name.strip()[:40]
            if not name:
                errors.append("Name is required.")
            try:
                freq_hz = round(float(freq_mhz) * 1e6)
                if not 24e6 <= freq_hz <= 1766e6:
                    errors.append("Frequency must be between 24 and 1766 MHz.")
            except ValueError:
                freq_hz = 0
                errors.append("Frequency must be a number in MHz, e.g. 157.4500.")
            device = device.strip() or "0"
            if not DEVICE_RE.match(device):
                errors.append("Device must be an index (0, 1…) or a dongle serial number.")
            gain = gain.strip().lower() or "auto"
            if gain != "auto":
                try:
                    if not 0 <= float(gain) <= 60:
                        raise ValueError
                except ValueError:
                    errors.append("Gain must be 'auto' or a number of dB (0–50).")
            try:
                ppm_i = int(ppm)
                if not -300 <= ppm_i <= 300:
                    raise ValueError
            except ValueError:
                ppm_i = 0
                errors.append("PPM must be a whole number between -300 and 300.")
            try:
                sq_i = int(squelch)
                if not 0 <= sq_i <= 1000:
                    raise ValueError
            except ValueError:
                sq_i = 0
                errors.append("Squelch must be a whole number, 0 to disable.")
            protos = [p for p in protocols if p in VALID_PROTOCOLS]
            if not protos:
                errors.append("Pick at least one protocol.")
            if pocsag_mode not in ("auto", "alpha", "numeric", "skyper"):
                pocsag_mode = "auto"
            for label, val in (("rtl_fm", extra_rtl), ("multimon-ng", extra_mm)):
                if not ALLOWED_ARG_RE.match(val):
                    errors.append(f"Extra {label} arguments contain characters that aren't allowed.")
                else:
                    try:
                        shlex.split(val)
                    except ValueError:
                        errors.append(f"Extra {label} arguments couldn't be parsed.")
            if errors:
                for e in errors:
                    flash(request, e, "error")
                return back(f"/config?edit={id}#channel-form" if id else "/config#channel-form")

            values = (name, freq_hz, device, gain, ppm_i, sq_i, ",".join(protos), pocsag_mode,
                      extra_rtl.strip(), extra_mm.strip(), 1 if enabled else 0)
            with db.transaction(conn):
                if id:
                    conn.execute(
                        "UPDATE channels SET name=?, freq_hz=?, device=?, gain=?, ppm=?, squelch=?, "
                        "protocols=?, pocsag_mode=?, extra_rtl=?, extra_mm=?, enabled=? WHERE id=?",
                        values + (id,))
                    action = "channel_update"
                else:
                    conn.execute(
                        "INSERT INTO channels (name, freq_hz, device, gain, ppm, squelch, protocols, "
                        "pocsag_mode, extra_rtl, extra_mm, enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        values)
                    action = "channel_add"
                db.bump_config_version(conn)
                db.audit(conn, user["username"], action,
                         f"{name} {freq_hz / 1e6:.4f} MHz dev {device} {','.join(protos)}")
            flash(request, f"Saved {name}. The decoder will restart with the new settings.")
            return back("/config")
        finally:
            conn.close()

    @app.post("/config/channel/{cid}/delete")
    async def delete_channel(request: Request, cid: int, csrf: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            row = conn.execute("SELECT name FROM channels WHERE id = ?", (cid,)).fetchone()
            if row:
                with db.transaction(conn):
                    conn.execute("DELETE FROM channels WHERE id = ?", (cid,))
                    db.bump_config_version(conn)
                    db.audit(conn, user["username"], "channel_delete", row["name"])
                flash(request, f"Deleted channel {row['name']}. Its past messages are kept.")
            return back("/config")
        finally:
            conn.close()

    @app.post("/config/settings")
    async def save_settings(request: Request, csrf: str = Form(""), retention_days: str = Form("30"),
                            dedupe_seconds: str = Form("0"), webhook_url: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            try:
                rd = int(retention_days)
                ds = int(dedupe_seconds)
                if not (0 <= rd <= 3650 and 0 <= ds <= 3600):
                    raise ValueError
            except ValueError:
                flash(request, "Retention must be 0–3650 days and de-duplication 0–3600 seconds.", "error")
                return back("/config#settings")
            webhook_url = webhook_url.strip()
            if webhook_url and not re.match(r"^https?://[^\s]+$", webhook_url):
                flash(request, "Webhook URL must start with http:// or https://", "error")
                return back("/config#settings")
            with db.transaction(conn):
                db.set_setting(conn, "retention_days", str(rd))
                db.set_setting(conn, "dedupe_seconds", str(ds))
                db.set_setting(conn, "webhook_url", webhook_url)
                db.bump_config_version(conn)
                db.audit(conn, user["username"], "settings_update",
                         f"retention={rd}d dedupe={ds}s webhook={'set' if webhook_url else 'none'}")
            flash(request, "Settings saved.")
            return back("/config#settings")
        finally:
            conn.close()

    @app.post("/config/alias")
    async def save_alias(request: Request, csrf: str = Form(""), capcode: str = Form(""),
                         label: str = Form(""), alert: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            capcode = capcode.strip()
            label = label.strip()[:60]
            if not capcode.isdigit() or not label:
                flash(request, "An alias needs a numeric capcode and a label.", "error")
                return back("/config#aliases")
            capcode = str(int(capcode))
            with db.transaction(conn):
                conn.execute(
                    "INSERT INTO aliases (capcode, label, alert) VALUES (?, ?, ?) "
                    "ON CONFLICT(capcode) DO UPDATE SET label = excluded.label, alert = excluded.alert",
                    (capcode, label, 1 if alert else 0))
                db.bump_config_version(conn)
                db.audit(conn, user["username"], "alias_save", f"{capcode} = {label}")
            flash(request, f"Saved alias for {capcode}.")
            return back("/config#aliases")
        finally:
            conn.close()

    @app.post("/config/alias/{aid}/delete")
    async def delete_alias(request: Request, aid: int, csrf: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            row = conn.execute("SELECT capcode FROM aliases WHERE id = ?", (aid,)).fetchone()
            if row:
                with db.transaction(conn):
                    conn.execute("DELETE FROM aliases WHERE id = ?", (aid,))
                    db.bump_config_version(conn)
                    db.audit(conn, user["username"], "alias_delete", row["capcode"])
            return back("/config#aliases")
        finally:
            conn.close()

    # --- users (admin) ----------------------------------------------------

    @app.get("/users", response_class=HTMLResponse)
    async def users(request: Request):
        conn, user = require_user(request, admin=True)
        try:
            rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
            return render(request, "users.html", user, users=rows, page_name="users")
        finally:
            conn.close()

    @app.post("/users/create")
    async def create_user(request: Request, csrf: str = Form(""), username: str = Form(""),
                          password: str = Form(""), role: str = Form("viewer"),
                          capcode_filter: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            username = username.strip()
            problem = None
            if not auth.USERNAME_RE.match(username):
                problem = "Usernames are 2–32 letters, digits, dots, dashes or underscores."
            elif role not in ("admin", "viewer"):
                problem = "Unknown role."
            elif auth.parse_capcode_filter(capcode_filter) is None:
                problem = "Capcode filter must be capcodes or ranges, e.g. 1234567, 2000000-2000099."
            else:
                problem = auth.password_problem(password)
            if not problem and conn.execute(
                    "SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                problem = f"User {username} already exists."
            if problem:
                flash(request, problem, "error")
                return back("/users")
            pw_hash = await asyncio.to_thread(auth.hash_password, password)
            with db.transaction(conn):
                conn.execute(
                    "INSERT INTO users (username, pw_hash, role, capcode_filter, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (username, pw_hash, role, capcode_filter.strip(), time.time()))
                db.audit(conn, user["username"], "user_create", f"{username} ({role})")
            flash(request, f"Created {username}.")
            return back("/users")
        finally:
            conn.close()

    @app.post("/users/{uid}/update")
    async def update_user(request: Request, uid: int, csrf: str = Form(""),
                          role: str = Form("viewer"), capcode_filter: str = Form(""),
                          active: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            target = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            if not target or role not in ("admin", "viewer"):
                return back("/users")
            if auth.parse_capcode_filter(capcode_filter) is None:
                flash(request, "Capcode filter must be capcodes or ranges, e.g. 1234567, 2000000-2000099.", "error")
                return back("/users")
            is_active = 1 if active else 0
            if (target["role"] == "admin" and (role != "admin" or not is_active)
                    and _active_admins(conn) <= 1):
                flash(request, "There must always be at least one active admin.", "error")
                return back("/users")
            with db.transaction(conn):
                conn.execute(
                    "UPDATE users SET role = ?, capcode_filter = ?, active = ? WHERE id = ?",
                    (role, capcode_filter.strip(), is_active, uid))
                db.audit(conn, user["username"], "user_update",
                         f"{target['username']}: role={role} active={is_active} "
                         f"filter={capcode_filter.strip() or 'all'}")
            flash(request, f"Updated {target['username']}.")
            return back("/users")
        finally:
            conn.close()

    @app.post("/users/{uid}/password")
    async def reset_password(request: Request, uid: int, csrf: str = Form(""),
                             password: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            target = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            if not target:
                return back("/users")
            problem = auth.password_problem(password)
            if problem:
                flash(request, problem, "error")
                return back("/users")
            pw_hash = await asyncio.to_thread(auth.hash_password, password)
            with db.transaction(conn):
                conn.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (pw_hash, uid))
                db.audit(conn, user["username"], "user_password_reset", target["username"])
            if uid == user["id"]:
                request.session["pw"] = pw_tag(pw_hash)
            flash(request, f"Password reset for {target['username']}. Their other sessions are signed out.")
            return back("/users")
        finally:
            conn.close()

    @app.post("/users/{uid}/delete")
    async def delete_user(request: Request, uid: int, csrf: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request, admin=True)
        try:
            target = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            if not target:
                return back("/users")
            if uid == user["id"]:
                flash(request, "You can't delete your own account.", "error")
                return back("/users")
            if target["role"] == "admin" and target["active"] and _active_admins(conn) <= 1:
                flash(request, "There must always be at least one active admin.", "error")
                return back("/users")
            with db.transaction(conn):
                conn.execute("DELETE FROM users WHERE id = ?", (uid,))
                db.audit(conn, user["username"], "user_delete", target["username"])
            flash(request, f"Deleted {target['username']}.")
            return back("/users")
        finally:
            conn.close()

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_log(request: Request, page: int = 1):
        conn, user = require_user(request, admin=True)
        try:
            page = max(1, page)
            total = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?",
                                (PAGE_SIZE, (page - 1) * PAGE_SIZE)).fetchall()
            return render(request, "audit.html", user, rows=rows, page=page,
                          pages=max(1, -(-total // PAGE_SIZE)), page_name="audit")
        finally:
            conn.close()

    # --- own account --------------------------------------------------------

    @app.get("/account", response_class=HTMLResponse)
    async def account(request: Request):
        conn, user = require_user(request)
        conn.close()
        return render(request, "account.html", user, page_name="account")

    @app.post("/account/password")
    async def change_password(request: Request, csrf: str = Form(""), current: str = Form(""),
                              new: str = Form(""), confirm: str = Form("")):
        check_csrf(request, csrf)
        conn, user = require_user(request)
        try:
            ok = await asyncio.to_thread(auth.verify_password, user["pw_hash"], current)
            problem = None
            if not ok:
                problem = "Current password is incorrect."
            elif new != confirm:
                problem = "New passwords don't match."
            else:
                problem = auth.password_problem(new)
            if problem:
                flash(request, problem, "error")
                return back("/account")
            pw_hash = await asyncio.to_thread(auth.hash_password, new)
            with db.transaction(conn):
                conn.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (pw_hash, user["id"]))
                db.audit(conn, user["username"], "password_change")
            request.session["pw"] = pw_tag(pw_hash)
            flash(request, "Password changed. Other sessions have been signed out.")
            return back("/account")
        finally:
            conn.close()

    @app.get("/healthz")
    async def healthz():
        conn = db.connect()
        try:
            hb = float(db.get_setting(conn, "decoder_heartbeat", "0") or 0)
            ok = time.time() - hb < 15
            return JSONResponse({"web": "ok", "decoder": "ok" if ok else "down"},
                                status_code=200 if ok else 503)
        finally:
            conn.close()

    return app


def _safe_next(nxt: str) -> str:
    # Only allow local paths, never another site.
    if not nxt or not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        return "/"
    return nxt


def _active_admins(conn) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]


def _csv_safe(value: str) -> str:
    # Stop spreadsheet apps treating message text as a formula.
    if value and value[0] in "=+-@\t\r":
        return "'" + value
    return value


def status_payload(conn) -> dict:
    hb = float(db.get_setting(conn, "decoder_heartbeat", "0") or 0)
    rows = conn.execute(
        "SELECT c.id, c.name, c.freq_hz, c.enabled, s.state, s.detail, s.msg_count, "
        "s.last_msg_at, s.started_at FROM channels c "
        "LEFT JOIN channel_status s ON s.channel_id = c.id ORDER BY c.name").fetchall()
    decoder_up = time.time() - hb < 15
    channels = []
    for r in rows:
        state = r["state"] or ("disabled" if not r["enabled"] else "unknown")
        if not decoder_up and r["enabled"]:
            state = "decoder down"
        channels.append({
            "id": r["id"], "name": r["name"], "freq": fmt_mhz(r["freq_hz"]),
            "state": state, "detail": r["detail"] or "", "count": r["msg_count"] or 0,
            "last": fmt_ts(r["last_msg_at"]) if r["last_msg_at"] else "",
        })
    return {"decoder": "up" if decoder_up else "down", "channels": channels}


def main() -> None:
    import uvicorn
    uvicorn.run(create_app(), host=settings.BIND, port=settings.PORT,
                proxy_headers=settings.TRUST_PROXY, forwarded_allow_ips="127.0.0.1",
                log_level="info")


if __name__ == "__main__":
    main()
