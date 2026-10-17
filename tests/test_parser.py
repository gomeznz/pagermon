from app.decoder import build_commands
from app.parser import parse_line


def test_pocsag_alpha():
    p = parse_line("POCSAG1200: Address: 1234567  Function: 3  Alpha:   HELLO WORLD<NUL><NUL>")
    assert p.protocol == "POCSAG1200"
    assert p.capcode == "1234567"
    assert p.function == "3"
    assert p.msg_type == "alpha"
    assert p.message == "HELLO WORLD"


def test_pocsag_numeric_padded_address():
    p = parse_line("POCSAG512: Address:   12345  Function: 0  Numeric: 0393141471")
    assert p.capcode == "12345"
    assert p.msg_type == "numeric"
    assert p.message == "0393141471"


def test_pocsag_tone_only():
    p = parse_line("POCSAG2400: Address:  777001  Function: 2 ")
    assert p.msg_type == "tone"
    assert p.message == ""


def test_pocsag_keeps_inner_control_tokens():
    p = parse_line("POCSAG1200: Address: 1  Function: 3  Alpha:   A<LF>B<ETX>")
    assert p.message == "A<LF>B"


def test_flex_pipe_format():
    p = parse_line("FLEX|2026-10-17 16:40:00|1600/2/K/A|05.120|001900100|ALN|Test | with pipe")
    assert p.protocol == "FLEX"
    assert p.capcode == "1900100"
    assert p.function == "1600/2"
    assert p.msg_type == "alpha"
    assert p.message == "Test | with pipe"


def test_flex_pipe_short_format():
    p = parse_line("FLEX|2018-03-13 17:16:53|1600/2/A|04.023|001234567|NUM|0123")
    assert p.capcode == "1234567"
    assert p.msg_type == "numeric"
    assert p.message == "0123"


def test_flex_pipe_tone():
    p = parse_line("FLEX|2026-10-17 16:42:00|1600/2/K/A|05.122|001900102|TON|")
    assert p.msg_type == "tone"
    assert p.message == ""


def test_flex_old_format():
    p = parse_line("FLEX: 2016-02-10 10:01:02 1600/2/A 05.110 [001234567] ALN Hello there")
    assert p.capcode == "1234567"
    assert p.function == "1600/2"
    assert p.message == "Hello there"


def test_ignores_noise():
    for line in ("", "multimon-ng 1.2.0", "Enabled demodulators: POCSAG512 POCSAG1200",
                 "Found 1 device(s):", "FLEX|garbage"):
        assert parse_line(line) is None


def test_build_commands():
    ch = {"device": "00000001", "freq_hz": 157450000, "ppm": -3, "squelch": 0,
          "gain": "40.2", "protocols": "POCSAG1200,FLEX,BOGUS", "pocsag_mode": "alpha",
          "extra_rtl": "-T", "extra_mm": "-e"}
    rtl, mm = build_commands(ch)
    assert rtl[:6] == ["rtl_fm", "-d", "00000001", "-f", "157450000", "-M"]
    assert "-g" in rtl and "40.2" in rtl and "-T" in rtl and rtl[-1] == "-"
    assert mm.count("-a") == 2 and "BOGUS" not in mm
    assert ["-f", "alpha"] == mm[mm.index("-f"):mm.index("-f") + 2]
    assert mm[-2:] == ["-e", "-"]
