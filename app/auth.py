"""Password hashing, login rate limiting and per-user capcode filters."""

import re
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Moderate parameters: comfortably under half a second on a Raspberry Pi 4.
_hasher = PasswordHasher(time_cost=2, memory_cost=32 * 1024, parallelism=2)

MIN_PASSWORD_LENGTH = 10
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(pw_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(pw_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# A real hash to verify against when the username doesn't exist, so a login
# for an unknown user takes as long as one for a known user.
_DUMMY_HASH = hash_password("not-a-real-password-0000")


def check_login(user_row, password: str) -> bool:
    if user_row is None:
        verify_password(_DUMMY_HASH, password)
        return False
    ok = verify_password(user_row["pw_hash"], password)
    return ok and bool(user_row["active"])


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > 256:
        return "Password is too long."
    return None


class LoginLimiter:
    """Locks out a username or client address after repeated failures."""

    def __init__(self, max_failures: int = 5, window: int = 900):
        self.max_failures = max_failures
        self.window = window
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        stamps = [t for t in self._fails.get(key, []) if now - t < self.window]
        if stamps:
            self._fails[key] = stamps
        else:
            self._fails.pop(key, None)
        return stamps

    def blocked(self, *keys: str) -> bool:
        now = time.time()
        with self._lock:
            return any(len(self._recent(k, now)) >= self.max_failures for k in keys)

    def fail(self, *keys: str) -> None:
        now = time.time()
        with self._lock:
            for k in keys:
                self._fails.setdefault(k, []).append(now)

    def clear(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._fails.pop(k, None)


_ITEM_RE = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")


def parse_capcode_filter(text: str) -> list[tuple[int, int]] | None:
    """Parse "1234567, 2000000-2000099" into ranges.

    Returns [] for a blank filter (meaning: see everything) and None if the
    text isn't valid.
    """
    ranges = []
    for part in (p.strip() for p in text.replace("\n", ",").split(",")):
        if not part:
            continue
        m = _ITEM_RE.match(part)
        if not m:
            return None
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if hi < lo:
            lo, hi = hi, lo
        ranges.append((lo, hi))
    return ranges


def capcode_sql(text: str, column: str = "m.capcode") -> tuple[str, list]:
    """SQL condition limiting messages.capcode to a user's filter."""
    ranges = parse_capcode_filter(text or "")
    if ranges is None:
        return "0=1", []  # unreadable filter: show nothing rather than everything
    if not ranges:
        return "1=1", []
    parts, params = [], []
    for lo, hi in ranges:
        if lo == hi:
            parts.append(f"{column} = ?")
            params.append(str(lo))
        else:
            parts.append(f"CAST({column} AS INTEGER) BETWEEN ? AND ?")
            params += [lo, hi]
    return "(" + " OR ".join(parts) + ")", params
