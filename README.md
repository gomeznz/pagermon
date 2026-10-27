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
- **Service tags**: mark a capcode as **Fire**, **Police** or **Ambulance** in one click from the Capcodes (or My capcodes) table. Keywords can carry a service too (e.g. "structure fire" → Fire), and a keyword's service beats the capcode's. Kiosks show a flame, police badge or caduceus beside the page, and alert webhooks include `"service"`. A blank capcode label takes the service name.
- **Keyword rules** (admins, on the Capcodes page): words or phrases in the message text that trigger an alert, are suppressed, or get a colour, on any capcode. Matches are highlighted in the message. Whole-word or anywhere matching, case-insensitive. Alerts always win over suppression, and a keyword's colour beats the capcode's. Webhook alerts include the matched keywords.
- **Kiosk displays** (admins create them on Config): a full-screen, read-only live view for a wall screen, opened from its own secret link with no sign-in. Large text, a clock, and alert pages that pulse red. Each kiosk can have its own capcode filter and theme. Links can be disabled, replaced or removed at any time, which cuts off open screens within seconds.
- **My capcodes** and **My kiosks** (every user): **My capcodes** has the same layout as the admin Capcodes page, for personal capcode labels, colours, alerts and suppression and personal keywords. **My kiosks** holds personal kiosks and a personal alert webhook (e.g. an ntfy topic). They sit on top of the shared rules and only change that user's own view. A user's admin-set capcode filter is always the outer limit, including on their kiosks. Admins set how many personal kiosks each user may have (Users page) and can disable or remove any of them (Config). Live has a **Notify me** option for browser pop-ups on alert pages (needs HTTPS, e.g. via Cloudflare Tunnel).
- **Locations and map** (turn on under Config → Locations): addresses in page text are looked up and shown on a **Map** page, on Live/History as a 📍 chip, and optionally on kiosks. A house, RAPID or property number gives a pin; a street, suburb or town on its own gives a shaded area circle.
- **Debug console** (admins): opened from Config in its own tab. Shows every raw line multimon-ng sends, rtl_fm and multimon-ng error output, and pipeline start/stop events, live. Lines that couldn't be parsed are highlighted, and the log can be filtered, paused, cleared or downloaded. The last 5,000 lines are kept.
- **Access control**: argon2-hashed passwords, admin and viewer roles, and optional per-user capcode filters (e.g. `1234567, 2000000-2000099`). Includes login lockout after 5 failures, CSRF protection, and sign-out of other sessions on password change. An **audit log** records sign-ins, config changes, user changes and exports.
- Runs as two hardened systemd services under an unprivileged `pager` user.

## Install on the Pi

Requires Raspberry Pi OS Bookworm or later, 64-bit (Lite is fine).

```bash
git clone <your repo> multipage   # or copy the folder across
cd multipage
sudo ./install.sh                     # add --rtlsdr-blog for an RTL-SDR Blog V4
```

The installer does the following:

- installs `rtl-sdr`, `multimon-ng` and Python
- blacklists the DVB-T TV driver
- creates the `pager` user and puts the app in `/opt/multipage`
- keeps data in `/var/lib/multipage`
- asks you to create the first admin account
- starts both services

Re-running it upgrades the code and keeps your data.

> **Upgrading from 1.2 or earlier:** the install folders were renamed from `pager-monitor` to `multipage` in 1.3. Re-running the installer moves your data (`/var/lib/pager-monitor` → `/var/lib/multipage`) and settings (`/etc/pager-monitor/pager-monitor.env` → `/etc/multipage/multipage.env`) across automatically and updates the paths inside the settings file. Your users, rules, kiosks and pages are kept. If you back up or script against the old paths, update those too.

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

Deployment settings (port, HTTPS cookies, session length) are in `/etc/multipage/multipage.env`. Restart both services after editing it.

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

## Kiosk displays

Create a kiosk under **Config → Kiosk displays**, then open its link on the screen. The link works without signing in, so treat it like a password, and use **New link** if it ever leaks. Each kiosk can show **all pages** (within its capcode filter) or **only pages forwarded to it**.

Every capcode and keyword rule has a **Kiosks** grid on the Capcodes page. For *All kiosks* and for each named kiosk you can pick:

- **Forward** — show the page there even if that kiosk wouldn't normally show it (outside its filter, forwarded-only mode, or suppressed).
- **Alert** — forward it and show it as an alert on that kiosk.
- **Suppress** — never show it on that kiosk.

For a given kiosk, a setting for that named kiosk beats an *All kiosks* setting, and Alert beats Suppress, which beats Forward. Kiosk alerts are display-only; webhooks still follow the rule's own Alert tick-box. Routing changes reach open screens within about ten seconds.

To turn a spare Raspberry Pi with a monitor into a dedicated display, install Raspberry Pi OS **with desktop**, then add this to autostart (`~/.config/labwc/autostart` on current Pi OS):

```
chromium --kiosk --noerrdialogs --disable-infobars --incognito "http://<pi-address>:8080/kiosk/<token>"
```

The page keeps the screen awake where the browser allows it, hides the mouse pointer when idle, and reconnects on its own after network or receiver restarts.

## Locations and map

Turn on **Config → Locations & map**, set a **default town or region** (used when a page names a street but no town), and paste one of your pages into **Try it** to check what's found.

- **Exact address** (pin): coordinates in the text, or an address whose house / RAPID / property number the geocoder knows (e.g. `115 YARROW ST INVERCARGILL`, `RAPID 1234 MAIN SOUTH RD`, `2/34 DEE ST`).
- **Area** (shaded circle sized to the street): a street with no number, or a number the map doesn't know (`SCRUB FIRE NORTH RD LORNEVILLE`, `SH1 EDENDALE`).
- **Town / place** (larger circle): just a suburb, town or place (`LOC: BLUFF WHARF`).

Addresses are found by street type (St, Rd, Ave, Cres, Tce, Hwy, SH1…), or after a marker word such as `LOC:` or `@` if your pages use one (configurable). Lookups use OpenStreetMap's Nominatim service by default, which in New Zealand includes LINZ addresses with rural RAPID numbers. They're cached and limited to one a second, as Nominatim's usage policy requires, and happen in the background so decoding never waits. **Turning lookups on sends the address part of matching pages to that service**; point the geocoder setting at your own Nominatim server if you'd rather nothing leaves your network. Map tiles come from OpenStreetMap by default (also configurable). The map library (Leaflet) is bundled with the app.

## Alert webhook

Pages to capcodes with **Alert** ticked are POSTed as JSON:

```json
{"id": 812, "ts": 1792209643.1, "channel": "Bench", "freq_hz": 157450000,
 "protocol": "POCSAG1200", "capcode": "1234567", "alias": "My test pager",
 "type": "alpha", "message": "ASI TEST PAGE 1"}
```

This works with ntfy, Home Assistant, Node-RED, n8n, or your own endpoint.

## Testing without a dongle

Set `PAGER_SIMULATE_FILE=/opt/multipage/app/sample_pages.txt` in the env file and restart. The decoder then replays those multimon-ng lines on every enabled channel instead of opening hardware.

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
