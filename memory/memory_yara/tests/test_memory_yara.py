from __future__ import annotations

import json

import pytest

from memory_yara.rules import RuleSyntaxError, parse_rules
from memory_yara.scanner import compile_rule, scan_buffer, scan_stream
from memory_yara.collect import scan_image
from memory_yara.cli import main


def _compile(text):
    return [compile_rule(r) for r in parse_rules(text)]


def test_simple_text_rule_matches():
    rule_text = '''
    rule Simple
    {
        strings:
            $a = "hello world"
        condition:
            $a
    }
    '''
    compiled = _compile(rule_text)
    hits = scan_buffer(compiled, b"xxx hello world xxx")
    assert len(hits) == 1
    assert hits[0].rule_name == "Simple"
    assert "$a" in hits[0].matched_strings


def test_no_match_no_hit():
    compiled = _compile('rule R { strings: $a = "zzz" condition: $a }')
    assert scan_buffer(compiled, b"nothing here") == []


def test_nocase_modifier():
    compiled = _compile(
        'rule R { strings: $a = "HELLO" nocase condition: $a }')
    hits = scan_buffer(compiled, b"say hello there")
    assert hits


def test_fullword_modifier():
    compiled = _compile(
        'rule R { strings: $a = "cat" fullword condition: $a }')
    assert scan_buffer(compiled, b"concatenate") == []
    assert scan_buffer(compiled, b"a cat sat") != []


def test_wide_modifier():
    compiled = _compile(
        'rule R { strings: $a = "hi" wide condition: $a }')
    data = "hi".encode("utf-16-le")
    assert scan_buffer(compiled, data) != []
    assert scan_buffer(compiled, b"hi") == []


def test_hex_pattern_exact():
    compiled = _compile(
        'rule R { strings: $a = { 4D 5A 90 00 } condition: $a }')
    assert scan_buffer(compiled, b"\x00\x4d\x5a\x90\x00\x00") != []
    assert scan_buffer(compiled, b"\x4d\x5a\x91\x00") == []


def test_hex_pattern_wildcard_byte():
    compiled = _compile(
        'rule R { strings: $a = { 4D 5A ?? 00 } condition: $a }')
    assert scan_buffer(compiled, b"\x4d\x5a\xff\x00") != []
    assert scan_buffer(compiled, b"\x4d\x5a\x00\x99") == []


def test_hex_pattern_jump_range():
    compiled = _compile(
        'rule R { strings: $a = { AA [2-4] BB } condition: $a }')
    assert scan_buffer(compiled, b"\xaa\x01\x02\xbb") != []
    assert scan_buffer(compiled, b"\xaa\x01\x02\x03\x04\xbb") != []
    assert scan_buffer(compiled, b"\xaa\xbb") == []  # zero bytes: too short


def test_hex_pattern_unsupported_syntax_raises():
    with pytest.raises(RuleSyntaxError):
        _compile('rule R { strings: $a = { 4D ?A } condition: $a }')


def test_and_or_not_condition():
    compiled = _compile('''
    rule R {
        strings:
            $a = "aaa"
            $b = "bbb"
        condition:
            $a and not $b
    }
    ''')
    assert scan_buffer(compiled, b"aaa only") != []
    assert scan_buffer(compiled, b"aaa and bbb") == []
    assert scan_buffer(compiled, b"bbb only") == []


def test_any_of_them():
    compiled = _compile('''
    rule R {
        strings:
            $a = "aaa"
            $b = "bbb"
            $c = "ccc"
        condition:
            any of them
    }
    ''')
    assert scan_buffer(compiled, b"just bbb here") != []
    assert scan_buffer(compiled, b"nothing") == []


def test_n_of_set():
    compiled = _compile('''
    rule R {
        strings:
            $a = "aaa"
            $b = "bbb"
            $c = "ccc"
        condition:
            2 of ($a, $b, $c)
    }
    ''')
    assert scan_buffer(compiled, b"aaa bbb") != []
    assert scan_buffer(compiled, b"just aaa") == []


def test_count_comparison():
    compiled = _compile('''
    rule R {
        strings:
            $a = "aa"
        condition:
            #a >= 3
    }
    ''')
    assert scan_buffer(compiled, b"aa bb aa cc aa") != []
    assert scan_buffer(compiled, b"aa only once") == []


def test_filesize_comparison():
    compiled = _compile('''
    rule R {
        strings:
            $a = "x"
        condition:
            $a and filesize < 10
    }
    ''')
    assert scan_buffer(compiled, b"x", filesize=5) != []
    assert scan_buffer(compiled, b"x", filesize=500) == []


def test_meta_reported():
    compiled = _compile('''
    rule R {
        meta:
            description = "test rule"
            severity = "high"
        strings:
            $a = "trigger"
        condition:
            $a
    }
    ''')
    hits = scan_buffer(compiled, b"trigger this")
    assert hits[0].meta["description"] == "test rule"
    assert hits[0].meta["severity"] == "high"


def test_multiple_rules_in_one_file():
    compiled = _compile('''
    rule First { strings: $a = "one" condition: $a }
    rule Second { strings: $b = "two" condition: $b }
    ''')
    hits = scan_buffer(compiled, b"one two")
    names = {h.rule_name for h in hits}
    assert names == {"First", "Second"}


def test_undefined_string_reference_raises():
    with pytest.raises(RuleSyntaxError):
        _compile('rule R { strings: $a = "x" condition: $b }')


def test_stream_scan_finds_match_across_chunk_boundary():
    compiled = _compile(
        'rule R { strings: $a = "boundarycrossingmarker" condition: $a }')
    filler = b"\x00" * 100
    data = filler + b"boundarycrossingmarker" + filler
    # split into small chunks so the marker straddles a chunk edge
    chunk_size = 50
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunks.append((i, data[i:i + chunk_size]))
    hits = scan_stream(compiled, iter(chunks), filesize=len(data))
    assert len(hits) == 1
    assert hits[0].matched_strings["$a"][0] == 100


def test_scan_image_end_to_end(tmp_path):
    rules_path = tmp_path / "r.yar"
    rules_path.write_text(
        'rule R { meta: description = "hit" strings: $a = "needle" '
        'condition: $a }')
    img_path = tmp_path / "mem.raw"
    img_path.write_bytes(b"\x00" * 1000 + b"needle" + b"\x00" * 1000)
    res = scan_image(str(img_path), str(rules_path))
    assert not res.warnings
    assert res.rows[0]["rule"] == "R"
    assert res.rows[0]["description"] == "hit"


def test_scan_image_no_match_warns(tmp_path):
    rules_path = tmp_path / "r.yar"
    rules_path.write_text('rule R { strings: $a = "zzz" condition: $a }')
    img_path = tmp_path / "mem.raw"
    img_path.write_bytes(b"\x00" * 100)
    res = scan_image(str(img_path), str(rules_path))
    assert not res.rows
    assert res.warnings


def test_bad_rule_syntax_warns(tmp_path):
    rules_path = tmp_path / "r.yar"
    rules_path.write_text('rule R { strings: $a = "x" condition: $undefined }')
    img_path = tmp_path / "mem.raw"
    img_path.write_bytes(b"\x00" * 100)
    res = scan_image(str(img_path), str(rules_path))
    assert not res.rows
    assert any("undefined" in w.lower() for w in res.warnings)


def test_one_bad_rule_does_not_block_others(tmp_path):
    rules_path = tmp_path / "r.yar"
    rules_path.write_text('''
    rule Bad { strings: $a = "x" condition: $undefined }
    rule Good { strings: $b = "needle" condition: $b }
    ''')
    img_path = tmp_path / "mem.raw"
    img_path.write_bytes(b"\x00" * 100 + b"needle" + b"\x00" * 100)
    res = scan_image(str(img_path), str(rules_path))
    assert any(r["rule"] == "Good" for r in res.rows)
    assert any("Bad" in w for w in res.warnings)


def test_starter_ruleset_parses_and_matches_eicar(tmp_path):
    from pathlib import Path as _P
    starter = _P(__file__).parent.parent / "memory_yara" / "rules" / \
        "starter.yar"
    img_path = tmp_path / "mem.raw"
    eicar = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-"
            b"FILE!$H+H*")
    img_path.write_bytes(b"\x00" * 200 + eicar + b"\x00" * 200)
    res = scan_image(str(img_path), str(starter))
    assert any(r["rule"] == "Eicar_Test_String" for r in res.rows)


def test_cli_csv_json(tmp_path):
    rules_path = tmp_path / "r.yar"
    rules_path.write_text('rule R { strings: $a = "needle" condition: $a }')
    img_path = tmp_path / "mem.raw"
    img_path.write_bytes(b"\x00" * 100 + b"needle" + b"\x00" * 100)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(img_path), "--rules", str(rules_path), "--csv",
              str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_starter_rules_flag(tmp_path):
    img_path = tmp_path / "mem.raw"
    img_path.write_bytes(b"\x00" * 100 + b"sekurlsa::logonpasswords" +
                         b"\x00" * 100)
    rc = main([str(img_path), "--starter-rules", "-q"])
    assert rc == 0


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path", "--starter-rules"])
    assert rc == 2


def test_csv_injection_guard():
    from memory_yara.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
