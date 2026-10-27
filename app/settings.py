"""Process-level settings, read from environment variables.

Everything a user would change day to day (frequencies, gain, retention,
users) lives in the database and is edited in the web UI. These are only the
deployment-level knobs, set in /etc/multipage/multipage.env.
"""

import os
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


DB_PATH = Path(os.environ.get("PAGER_DB", "/var/lib/multipage/pager.db"))

# Web server
BIND = os.environ.get("PAGER_BIND", "0.0.0.0")
PORT = int(os.environ.get("PAGER_PORT", "8080"))
# Set true when served over HTTPS (e.g. behind Caddy) so cookies are Secure-only.
SECURE_COOKIES = _bool("PAGER_SECURE_COOKIES", False)
SESSION_HOURS = int(os.environ.get("PAGER_SESSION_HOURS", "12"))
# Trust X-Forwarded-For from a local reverse proxy for login rate limiting.
TRUST_PROXY = _bool("PAGER_TRUST_PROXY", False)

# Decoder
RTL_FM = os.environ.get("PAGER_RTL_FM", "rtl_fm")
MULTIMON = os.environ.get("PAGER_MULTIMON", "multimon-ng")
# Path to a text file of multimon-ng output lines to replay instead of using
# real hardware. Handy for testing the web UI on a desk with no dongle.
SIMULATE_FILE = os.environ.get("PAGER_SIMULATE_FILE", "")
SIMULATE_INTERVAL = float(os.environ.get("PAGER_SIMULATE_INTERVAL", "3"))
