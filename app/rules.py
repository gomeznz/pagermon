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
  * service    — Fire / Police / Ambulance, chosen the same way as colour:
                 the first matching keyword with a service, else the capcode's
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
    service: str = ""


@dataclass
class Result:
    alert: bool = False
    suppressed: bool = False
    colour: str = ""
    service: str = ""
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
        service=(row["service"] if "service" in row.keys() else "") or "",
    )


def load_rules(conn: sqlite3.Connection) -> list[Rule]:
    return [compile_rule(r) for r in conn.execute("SELECT * FROM keywords ORDER BY id")]


def evaluate(message: str, rules: list[Rule], cap_alert: bool = False,
             cap_suppress: bool = False, cap_colour: str = "", cap_service: str = "") -> Result:
    res = Result()
    kw_alert = kw_suppress = False
    kw_colour = kw_service = ""
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
            if rule.service and not kw_service:
                kw_service = rule.service
            for m in hits:
                res.spans.append((m.start(), m.end(), rule.colour))
    res.alert = bool(cap_alert or kw_alert)
    res.suppressed = bool((cap_suppress or kw_suppress) and not res.alert)
    res.colour = kw_colour or cap_colour or ""
    res.service = kw_service or cap_service or ""
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
    """Return (show, alert) for one page on one shared kiosk."""
    keys = ([("capcode", alias_id)] if alias_id else []) + [("keyword", k) for k in keyword_ids]
    specific, everywhere = route_actions(routes, keys, kiosk_id)
    return decide([specific, everywhere], in_filter=in_filter, forwarded_only=forwarded_only,
                  suppressed=suppressed, alert=alert)


# --- per-user view -------------------------------------------------------------
#
# Each user can add personal capcode and keyword rules that sit on top of the
# shared ones and only change what *they* see (and their own kiosks):
#   * label    — the personal label if set, else the shared one
#   * colour   — personal colour (keyword first, then capcode), else shared colour
#   * service  — the same order as colour
#   * alert    — shared alert OR personal alert
#   * suppress — shared or personal suppression, unless the page alerts
# Shared kiosks and the shared webhook only ever use the shared rules.

@dataclass
class View:
    shared: list
    personal_caps: dict = field(default_factory=dict)   # capcode -> user_aliases row
    personal: list = field(default_factory=list)        # compiled user_keywords


@dataclass
class Shown:
    alert: bool
    suppressed: bool
    colour: str
    label: str
    keywords: list
    service: str
    spans: list
    shared_keyword_ids: list
    personal_keyword_ids: list
    personal_alias_id: int | None
    personal_alert: bool


def load_view(conn: sqlite3.Connection, user_id: int | None = None) -> View:
    shared = load_rules(conn)
    if not user_id:
        return View(shared)
    caps = {r["capcode"]: dict(r) for r in
            conn.execute("SELECT * FROM user_aliases WHERE user_id = ?", (user_id,))}
    personal = [compile_rule(r) for r in
                conn.execute("SELECT * FROM user_keywords WHERE user_id = ? ORDER BY id", (user_id,))]
    return View(shared, caps, personal)


def apply_view(message: str, capcode: str, view: View, cap_alert=0, cap_suppress=0,
               cap_colour: str = "", cap_label: str = "", cap_service: str = "") -> Shown:
    s = evaluate(message, view.shared, cap_alert, cap_suppress, cap_colour, cap_service)
    pc = view.personal_caps.get(capcode) or {}
    p = evaluate(message, view.personal, pc.get("alert", 0), pc.get("suppress", 0), pc.get("colour", ""),
                 pc.get("service", "") or "")
    alert = s.alert or p.alert
    keywords = list(dict.fromkeys(s.keywords + p.keywords))
    return Shown(
        alert=alert,
        suppressed=(s.suppressed or p.suppressed) and not alert,
        colour=p.colour or s.colour,
        label=pc.get("label") or cap_label or "",
        keywords=keywords,
        service=p.service or s.service,
        spans=_merge(s.spans + p.spans),
        shared_keyword_ids=s.keyword_ids,
        personal_keyword_ids=p.keyword_ids,
        personal_alias_id=pc.get("id"),
        personal_alert=p.alert,
    )


def load_user_routes(conn: sqlite3.Connection, user_id: int) -> dict:
    routes: dict = {}
    for r in conn.execute("SELECT rule_type, rule_id, kiosk_id, action FROM user_routes WHERE user_id = ?",
                          (user_id,)):
        routes.setdefault((r["rule_type"], r["rule_id"]), []).append((r["kiosk_id"], r["action"]))
    return routes


def route_actions(routes: dict, keys, kiosk_id: int) -> tuple[set, set]:
    """Actions from these rules aimed at this kiosk, and at "all kiosks" (id 0)."""
    specific, everywhere = set(), set()
    for key in keys:
        for kid, action in routes.get(key, ()):
            if kid == kiosk_id:
                specific.add(action)
            elif kid == 0:
                everywhere.add(action)
    return specific, everywhere


def decide(levels, *, in_filter: bool, forwarded_only: bool, suppressed: bool,
           alert: bool) -> tuple[bool, bool]:
    """(show, alert) from action sets in priority order; the first non-empty set wins."""
    for actions in levels:
        if actions:
            if "alert" in actions:
                return True, True
            if "suppress" in actions:
                return False, False
            return True, alert  # forward
    return (in_filter and not suppressed and not forwarded_only), alert
