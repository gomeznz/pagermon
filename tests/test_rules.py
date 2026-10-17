from app.rules import compile_rule, evaluate, segments


def rule(id, keyword, match="word", alert=0, suppress=0, colour=""):
    return compile_rule({"id": id, "keyword": keyword, "match": match, "alert": alert,
                         "suppress": suppress, "colour": colour})


def test_whole_word_vs_contains():
    word = [rule(1, "fire", colour="red")]
    assert evaluate("Structure FIRE at depot", word).keywords == ["fire"]
    assert evaluate("firewall reboot", word).keywords == []
    anywhere = [rule(1, "fire", match="contains")]
    assert evaluate("firewall reboot", anywhere).keywords == ["fire"]


def test_phrase_tolerates_spacing():
    r = [rule(1, "test page")]
    assert evaluate("ASI TEST   PAGE 1", r).keywords == ["test page"]


def test_alert_beats_suppress():
    rules = [rule(1, "noise", suppress=1), rule(2, "urgent", alert=1)]
    assert evaluate("noise only", rules).suppressed is True
    res = evaluate("urgent noise", rules)
    assert res.alert is True and res.suppressed is False
    # capcode suppressed but keyword alerts -> shown and alerts
    res = evaluate("urgent", rules, cap_suppress=1)
    assert res.alert and not res.suppressed
    # capcode alerts, keyword suppresses -> shown
    assert evaluate("noise", rules, cap_alert=1).suppressed is False


def test_colour_priority_and_spans():
    rules = [rule(1, "alpha", colour="blue"), rule(2, "beta", colour="red")]
    res = evaluate("beta then alpha", rules, cap_colour="green")
    assert res.colour == "blue"  # first rule in list order with a colour
    assert evaluate("nothing", rules, cap_colour="green").colour == "green"
    assert res.spans == [(0, 4, "red"), (10, 15, "blue")]
    assert segments("beta then alpha", res.spans) == [
        ("beta", True, "red"), (" then ", False, ""), ("alpha", True, "blue")]


def test_regex_characters_are_literal():
    r = [rule(1, "a.b*", match="contains")]
    assert evaluate("xa.b*y", r).keywords == ["a.b*"]
    assert evaluate("aXbbb", r).keywords == []
