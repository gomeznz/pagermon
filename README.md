<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="app/static/logo-dark.svg">
    <img src="app/static/logo.svg" alt="MultipagePlus" width="360">
  </picture>
</p>

# MultipagePlus

POCSAG and FLEX paging receiver for a Raspberry Pi 4 and an RTL-SDR dongle, with a web front end, configuration UI and access control. For testing your own pagers and paging equipment.

```
RTL-SDR ─▶ rtl_fm ─▶ multimon-ng ─▶ decoder service ─▶ SQLite ◀─ web app ─▶ browser
                                        │                         (live feed, history,
                                        └─▶ webhook alerts         config, users, audit)
```

## What you get

- **Live feed** over WebSocket, with filtering, pause and channel status.
- **History** with search by text, capcode or range, protocol, channel and date, plus CSV export.
- **Config page** (admins): channels (frequency, dongle, gain, PPM, squelch, protocols), retention, de-duplication and alert webhook. Saving applies within a few seconds; nothing needs restarting by hand.
- **Capcodes page** (admins): label capcodes, give each a display colour, flag them for alerts, or suppress noisy ones, with page counts and last-seen times. Admins can click any capcode on the Live or History screens to jump straight to it.
- **Access control**: argon2-hashed passwords, admin and viewer roles, and optional per-user capcode filters (e.g. `1234567, 2000000-2000099`). Includes login lockout after 5 failures, CSRF protection, and sign-out of other sessions on password change. An **audit log** records sign-ins, config changes, user changes and exports.
- Runs as two hardened systemd services under an unprivileged `pager` user.

## Install on the Pi

Requires Raspberry Pi OS Bookworm or later, 64-bit (Lite is fine).

```bash
git clone <your repo> pager-monitor   # or copy the folder across
cd pager-monitor
sudo ./install.sh                     # add --rtlsdr-blog for an RTL-SDR Blog V4
```

The installer does the following:

- installs `rtl-sdr`, `multimon-ng` and Python
- blacklists the DVB-T TV driver
- creates the `pager` user and puts the app in `/opt/pager-monitor`
- keeps data in `/var/lib/pager-monitor`
- asks you to create the first admin account
- starts both services

Re-running it upgrades the code and keeps your data.

> **RTL-SDR Blog V4:** the Debian `rtl-sdr` package doesn't support the V4's tuner properly. Use `--rtlsdr-blog` to build the RTL-SDR Blog driver instead (it also works with V3 and generic dongles).

Then open `http://<pi-address>:8080/`, sign in, go to **Config** and add a channel.

### First-run checklist

1. `rtl_test -t` should find the dongle. If it reports the device as busy, reboot so the TV driver is released.
2. Find your PPM error. Either run `rtl_test -p` for a few minutes, or tune a known signal and adjust until it decodes cleanly. A TCXO dongle is usually within ±1 ppm.
3. Start with **gain** on `auto`, **squelch** at `0` and all protocols ticked. Once you know what your transmitter sends, untick the protocols you don't need. This saves CPU and avoids false decodes.
4. On the **Capcodes** page, add a label for each of your test pager capcodes. Tick **Alert** if you want those pages sent to a webhook.
5. Tick **Suppress** on any noisy capcode you don't care about (a label is optional). Its pages are still recorded but hidden on the Live screen unless you tick **Show suppressed**. History and CSV export include them, marked as suppressed. Suppressed capcodes never trigger alerts.

## Everyday admin

```bash
sudo pager-admin list-users
sudo pager-admin add-user sam --role viewer
sudo pager-admin reset-password alex     # also re-enables a disabled account
journalctl -u pager-decoder -f           # decoder log, including rtl_fm errors
journalctl -u pager-web -f
curl http://localhost:8080/healthz       # 200 when the decoder is running, 503 if not
```

Deployment settings (port, HTTPS cookies, session length) are in `/etc/pager-monitor/pager-monitor.env`. Restart both services after editing it.

## Remote access

Keep it off the open internet. The easiest secure option is **Tailscale** on the Pi: you browse to its tailnet address and nothing is exposed. To use HTTPS on the LAN, put **Caddy** in front:

```
# /etc/caddy/Caddyfile
pager.local {
    tls internal
    reverse_proxy 127.0.0.1:8080
}
```

Then in the env file set `PAGER_BIND=127.0.0.1`, `PAGER_SECURE_COOKIES=true` and `PAGER_TRUST_PROXY=true`.

## Alert webhook

Pages to capcodes with **Alert** ticked are POSTed as JSON:

```json
{"id": 812, "ts": 1792209643.1, "channel": "Bench", "freq_hz": 157450000,
 "protocol": "POCSAG1200", "capcode": "1234567", "alias": "My test pager",
 "type": "alpha", "message": "ASI TEST PAGE 1"}
```

This works with ntfy, Home Assistant, Node-RED, n8n, or your own endpoint.

## Testing without a dongle

Set `PAGER_SIMULATE_FILE=/opt/pager-monitor/app/sample_pages.txt` in the env file and restart. The decoder then replays those multimon-ng lines on every enabled channel instead of opening hardware.

For development on any machine:

```bash
python3 -m venv venv && venv/bin/pip install -r requirements.txt pytest httpx
venv/bin/python -m pytest
export PAGER_DB=./dev.db PAGER_SIMULATE_FILE=app/sample_pages.txt
venv/bin/python -m app.cli add-user alex
venv/bin/python -m app.decoder &   venv/bin/python -m app.web
```

## Limits of this version, and where to take it next

- **One frequency per dongle.** This is `rtl_fm`'s limit. Several frequencies within ~2 MHz could share one dongle by replacing `rtl_fm` with a wideband capture plus a polyphase channeliser, written in C or numpy.
- **Decoding is multimon-ng's.** POCSAG is solid. FLEX coverage depends on the multimon-ng version; Bookworm ships 1.2.x, and newer builds add `FLEX_NEXT`. A custom decoder would add per-message signal level, BCH-corrected bit counts and better 4-FSK handling.
- **Paging traffic you don't own:** the Radiocommunications Act 1989 restricts using or disclosing the contents of messages not intended for you. Per-user capcode filters and retention help keep the system scoped to your own testing.

## Layout

```
app/decoder.py    receive pipeline supervisor, storage, alerts, retention
app/parser.py     multimon-ng output → structured pages (POCSAG, FLEX)
app/web.py        FastAPI app: pages, WebSocket feed, auth, admin
app/auth.py       password hashing, lockout, capcode filters
app/db.py         SQLite schema and helpers
app/cli.py        pager-admin command
install.sh        Raspberry Pi installer
systemd/          service units
tests/            pytest suite
```
