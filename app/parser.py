"""Parse multimon-ng output lines into structured page messages.

multimon-ng's POCSAG output is stable across versions. Its FLEX output has
changed format a few times, so the FLEX parser works on the pipe-separated
fields by shape rather than by fixed position, and also accepts the older
space-separated format.
"""

import re
from dataclasses import dataclass

POCSAG_RE = re.compile(
    r"^(?P<proto>POCSAG(?:512|1200|2400)):\s+"
    r"Address:\s*(?P<addr>\d+)\s+"
    r"Function:\s*(?P<func>\d+)"
    r"(?:\s+(?P<kind>Alpha|Numeric|Skyper):\s*(?P<msg>.*))?\s*$"
)

# Older multimon-ng: "FLEX: 2016-02-10 10:01:02 1600/2/A 05.110 [001234567] ALN Message"
FLEX_OLD_RE = re.compile(
    r"^(?P<proto>FLEX(?:_NEXT)?):\s+\S+\s+\S+\s+"
    r"(?P<rate>\d+/\d+)(?:/\S+)?\s+\S+\s+"
    r"\[(?P<addr>\d+)\]\s+(?P<kind>[A-Z]{3})\s?(?P<msg>.*)$"
)

FLEX_TYPES = {"ALN", "NUM", "TON", "BIN", "UNK", "SNM", "SFN", "HEX", "SEC"}
TYPE_NAMES = {
    "Alpha": "alpha",
    "Numeric": "numeric",
    "Skyper": "alpha",
    "ALN": "alpha",
    "NUM": "numeric",
    "SNM": "numeric",
    "SFN": "numeric",
    "TON": "tone",
    "BIN": "binary",
    "HEX": "binary",
}

# Control characters multimon-ng renders as <XXX> tokens at the end of alpha
# messages. They carry no meaning for display, so trailing ones are removed.
_TRAILING_CTRL = re.compile(r"(?:<(?:NUL|ETX|EOT|ETB|EOM|DEL|ENQ)>)+\s*$")


@dataclass
class Page:
    protocol: str  # e.g. POCSAG1200, FLEX, FLEX 3200/4
    capcode: str  # normalised: decimal digits, no leading zeros
    function: str  # POCSAG function bits (0-3); FLEX rate/levels
    msg_type: str  # alpha | numeric | tone | binary | other
    message: str
    raw: str


def _norm_capcode(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return str(int(digits)) if digits else value.strip()


def _clean(msg: str) -> str:
    return _TRAILING_CTRL.sub("", msg).rstrip()


def parse_line(line: str) -> Page | None:
    """Return a Page for a decoded message line, or None for anything else."""
    line = line.rstrip("\r\n")
    if not line:
        return None

    m = POCSAG_RE.match(line)
    if m:
        kind = m.group("kind")
        return Page(
            protocol=m.group("proto"),
            capcode=_norm_capcode(m.group("addr")),
            function=m.group("func"),
            msg_type=TYPE_NAMES.get(kind, "tone") if kind else "tone",
            message=_clean(m.group("msg") or ""),
            raw=line,
        )

    if line.startswith(("FLEX|", "FLEX_NEXT|")):
        return _parse_flex_pipe(line)

    m = FLEX_OLD_RE.match(line)
    if m:
        kind = m.group("kind")
        return Page(
            protocol="FLEX",
            capcode=_norm_capcode(m.group("addr")),
            function=m.group("rate"),
            msg_type=TYPE_NAMES.get(kind, "other"),
            message=_clean(m.group("msg")),
            raw=line,
        )

    return None


def _parse_flex_pipe(line: str) -> Page | None:
    fields = line.split("|")
    rate = ""
    rate_idx = -1
    for i, f in enumerate(fields[1:], start=1):
        if re.fullmatch(r"\d{3,4}/\d(?:/\S+)?", f.strip()):
            rate = "/".join(f.strip().split("/")[:2])
            rate_idx = i
            break

    type_idx = -1
    for i, f in enumerate(fields[1:], start=1):
        if f.strip() in FLEX_TYPES:
            type_idx = i
            break

    capcode = ""
    search_end = type_idx if type_idx > 0 else len(fields)
    for f in fields[max(rate_idx + 1, 1):search_end]:
        token = f.strip().split(" ")[0]
        if re.fullmatch(r"\d{4,10}", token):
            capcode = token
            break
    if not capcode:
        return None

    if type_idx > 0:
        kind = fields[type_idx].strip()
        message = "|".join(fields[type_idx + 1:])
    else:
        kind = ""
        message = fields[-1]

    proto = fields[0].strip()
    return Page(
        protocol=proto,
        capcode=_norm_capcode(capcode),
        function=rate,
        msg_type=TYPE_NAMES.get(kind, "other") if kind else "other",
        message=_clean(message),
        raw=line,
    )
