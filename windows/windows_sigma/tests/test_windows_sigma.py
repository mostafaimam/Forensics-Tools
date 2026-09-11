from __future__ import annotations

import json

import pytest

import _synth as S

from windows_sigma import condition as C
from windows_sigma import yamlmini
from windows_sigma.rules import load_dir
from windows_sigma.engine import run_rules
from windows_sigma.cli import main, _BUNDLED


def test_yamlmini_roundtrip():
    doc = yamlmini.load("""
title: t
detection:
    sel:
        Image|endswith:
            - '\\\\a.exe'
            - '\\\\b.exe'
    condition: sel
tags:
    - x
    - y
""")
    assert doc["title"] == "t"
    # this mini-parser treats single-quoted scalars literally (no
    # backslash-escape interpretation, matching plain YAML semantics)
    assert doc["detection"]["sel"]["Image|endswith"] == \
        ["\\\\a.exe", "\\\\b.exe"]
    assert doc["tags"] == ["x", "y"]


def test_condition_grammar():
    names = {"a", "b1", "b2"}
    node = C.parse("a and (1 of b*)", names)
    assert C.evaluate(node, {"a": True, "b1": False, "b2": True}, names)
    assert not C.evaluate(node, {"a": False, "b1": True, "b2": True}, names)
    node2 = C.parse("not a", names)
    assert C.evaluate(node2, {"a": False}, names)


def test_bundled_rules_load():
    rules, errors = load_dir(str(_BUNDLED))
    assert not errors
    assert len(rules) >= 5
    assert any(r.title.lower().startswith("encoded") for r in rules)


def test_engine_hits(tmp_path):
    evtx = tmp_path / "evtx.csv"
    ps = tmp_path / "ps.csv"
    S.build_evtx(evtx)
    S.build_pslogging(ps)
    rules, _ = load_dir(str(_BUNDLED))
    hits = run_rules(rules, [str(evtx), str(ps)])
    titles = {h.rule_title for h in hits}
    assert any("Event Log Cleared" in t for t in titles)
    assert any("LOLBin" in t for t in titles)
    assert any("Encoded" in t for t in titles)
    assert any("LSASS" in t for t in titles)
    # the benign rows must not appear
    benign_hits = [h for h in hits if h.row.get("EventId") == "4624" or
                  h.row.get("scriptblock_id") == "sb-3"]
    assert not benign_hits


def test_min_level_filter(tmp_path):
    evtx = tmp_path / "evtx.csv"
    S.build_evtx(evtx)
    rules, _ = load_dir(str(_BUNDLED))
    all_hits = run_rules(rules, [str(evtx)])
    high_hits = run_rules(rules, [str(evtx)], min_level="critical")
    assert len(high_hits) <= len(all_hits)
    assert all(h.level == "critical" for h in high_hits)


def test_custom_rule_dir(tmp_path):
    (tmp_path / "custom.yml").write_text("""
title: Custom Test Rule
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 4624
    condition: selection
""")
    evtx = tmp_path / "evtx.csv"
    S.build_evtx(evtx)
    rules, errors = load_dir(str(tmp_path))
    assert not errors
    hits = run_rules(rules, [str(evtx)])
    assert any(h.rule_title == "Custom Test Rule" for h in hits)


def test_cli(tmp_path):
    evtx = tmp_path / "evtx.csv"
    ps = tmp_path / "ps.csv"
    S.build_evtx(evtx)
    S.build_pslogging(ps)
    js = tmp_path / "o.json"
    csv_p = tmp_path / "o.csv"
    rc = main([str(evtx), str(ps), "--csv", str(csv_p), "--json", str(js),
               "-q"])
    assert rc == 1     # high/critical hits present -> nonzero
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert rows
    assert any(r["level"] == "critical" for r in rows)


def test_list_rules(capsys):
    rc = main(["--list-rules"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Event Log Cleared" in out


def test_csv_injection_guard():
    from windows_sigma.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
