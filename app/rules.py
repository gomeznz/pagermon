"""Keyword rules and how they combine with capcode settings.

Shared by the decoder (which sends alerts) and the web app (which colours,
highlights and hides pages), so both always agree on what a page means.

How a page's settings are worked out:
  * alert      — the capcode has Alert ticked, or any matching keyword does
  * suppressed — the capcode or any matching keyword is suppressed, unless the
                 page alerts: alerts always win, so an alerting page is never
                 hidden
  * colour     — the first matching keyword that has a colour, otherwise the
                 capcode's colour
Keywords are case-insensitive and match whole words by default ("fire" does
not match "firewall"); a rule can be switched to match anywhere instead.
Matching applies to past pages as well as new ones, like capcode settings.
"""

import re
import sqlite3
from dataclasses import dataclass, field

MATCH_MODES = ("word", "contains")


@dataclass
class Rule:
    id: int
    keyword: str
    match: str
    alert: bool
    suppress: bool
    colour: str
    pattern: re.Pattern = field(repr=False)


@dataclass
class Result:
    alert: bool = False
    suppressed: bool = False
    colour: str = ""
    keywords: list[str] = field(default_factory=list)
    keyword_ids: list[int] = field(default_factory=list)
    spans: list[tuple[int, int, str]] = field(default_factory=list)  # start, end, colour


def compile_rule(row) -> Rule:
    kw = row["keyword"]
    body = re.escape(kw).replace(r"\ ", r"\s+")  # a phrase tolerates any spacing
    if row["match"] == "word":
        body = r"(?<!\w)" + body + r"(?!\w)"
    return Rule(
        id=row["id"], keyword=kw, match=row["match"], alert=bool(row["alert"]),
        suppress=bool(row["suppress"]), colour=row["colour"] or "",
        pattern=re.compile(body, re.IGNORECASE),
    )


def load_rules(conn: sqlite3.Connection) -> list[Rule]:
    return [compile_rule(r) for r in conn.execute("SELECT * FROM keywords ORDER BY id")]


def evaluate(message: str, rules: list[Rule], cap_alert: bool = False,
             cap_suppress: bool = False, cap_colour: str = "") -> Result:
    res = Result()
    kw_alert = kw_suppress = False
    kw_colour = ""
    if message and rules:
        for rule in rules:
            hits = list(rule.pattern.finditer(message))
            if not hits:
                continue
            res.keywords.append(rule.keyword)
            res.keyword_ids.append(rule.id)
            kw_alert |= rule.alert
            kw_suppress |= rule.suppress
            if rule.colour and not kw_colour:
                kw_colour = rule.colour
            for m in hits:
                res.spans.append((m.start(), m.end(), rule.colour))
    res.alert = bool(cap_alert or kw_alert)
    res.suppressed = bool((cap_suppress or kw_suppress) and not res.alert)
    res.colour = kw_colour or cap_colour or ""
    res.spans = _merge(res.spans)
    return res


def _merge(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Sort and drop overlaps so highlighting never nests."""
    out: list[tuple[int, int, str]] = []
    for s in sorted(spans):
        if out and s[0] < out[-1][1]:
            prev = out[-1]
            out[-1] = (prev[0], max(prev[1], s[1]), prev[2])
        else:
            out.append(s)
    return out


def segments(message: str, spans) -> list[tuple[str, bool, str]]:
    """Split a message into (text, highlighted, colour) pieces for display."""
    out, pos = [], 0
    for start, end, colour in spans:
        if start > pos:
            out.append((message[pos:start], False, ""))
        out.append((message[start:end], True, colour))
        pos = end
    if pos < len(message):
        out.append((message[pos:], False, ""))
    return out


# --- kiosk routing -----------------------------------------------------------
#
# Capcode and keyword rules can carry per-kiosk actions, stored in kiosk_routes
# as (rule_type, rule_id, kiosk_id, action) with kiosk_id 0 meaning "all kiosks".
#
# For one page on one kiosk:
#   * actions naming that kiosk beat "all kiosks" actions
#   * then:  alert  > suppress > forward
#       alert    — show it, styled as an alert
#       suppress — never show it on this kiosk
#       forward  — show it even if the kiosk's capcode filter, its
#                  "only forwarded pages" mode or global suppression would hide it
#   * with no kiosk action, the kiosk follows its normal settings: show the page
#     if it is in the kiosk's capcode filter, not suppressed, and the kiosk shows
#     all pages; alert styling follows the page's own alert.

KIOSK_ACTIONS = ("forward", "alert", "suppress")
RULE_TYPES = ("capcode", "keyword")


def load_routes(conn: sqlite3.Connection) -> dict[tuple[str, int], list[tuple[int, str]]]:
    routes: dict[tuple[str, int], list[tuple[int, str]]] = {}
    for r in conn.execute("SELECT rule_type, rule_id, kiosk_id, action FROM kiosk_routes"):
        routes.setdefault((r["rule_type"], r["rule_id"]), []).append((r["kiosk_id"], r["action"]))
    return routes


def kiosk_decision(kiosk_id: int, routes: dict, alias_id, keyword_ids, *, in_filter: bool,
                   forwarded_only: bool, suppressed: bool, alert: bool) -> tuple[bool, bool]:
    """Return (show, alert) for one page on one kiosk."""
    keys = ([("capcode", alias_id)] if alias_id else []) + [("keyword", k) for k in keyword_ids]
    specific, everywhere = set(), set()
    for key in keys:
        for kid, action in routes.get(key, ()):
            if kid == kiosk_id:
                specific.add(action)
            elif kid == 0:
                everywhere.add(action)
    actions = specific or everywhere
    if "alert" in actions:
        return True, True
    if "suppress" in actions:
        return False, False
    if "forward" in actions:
        return True, alert
    return (in_filter and not suppressed and not forwarded_only), alert
