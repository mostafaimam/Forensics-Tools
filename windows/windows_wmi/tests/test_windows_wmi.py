from __future__ import annotations

import json

import pytest

import _synth as S

from windows_wmi.collect import collect
from windows_wmi.cli import main


def _rows(tmp_path):
    p = tmp_path / "OBJECTS.DATA"
    p.write_bytes(S.build_objects())
    return collect([str(p)])


def test_extract_triad(tmp_path):
    res = _rows(tmp_path)
    by_type = {}
    for r in res.rows:
        by_type.setdefault(r["type"], []).append(r)
    assert by_type["filter"]
    assert by_type["consumer"]
    assert by_type["binding"]

    f = next(r for r in by_type["filter"]
             if r["name"] == "SecurityUpdaterFilter")
    assert "Win32_Process" in f["query"]

    c = next(r for r in by_type["consumer"]
             if r["class"] == "CommandLineEventConsumer")
    assert "powershell" in c["action"].lower()
    assert c["severity"] == "high"
    assert "living-off-the-land" in c["notable"]
    assert "encoded / obfuscated / hidden" in c["notable"]

    b = by_type["binding"][0]
    assert b["filter"] == "SecurityUpdaterFilter"
    assert b["consumer"] == "SecurityUpdaterConsumer"
    # binding inherits the filter query via the join
    assert "Win32_Process" in b["query"]


def test_script_consumer_and_namespace(tmp_path):
    res = _rows(tmp_path)
    sc = next(r for r in res.rows
              if r["class"] == "ActiveScriptEventConsumer")
    assert sc["severity"] == "high"
    assert "in-memory script consumer" in sc["notable"]
    assert "non-default namespace" in sc["notable"]


def test_cli_filters(tmp_path):
    p = tmp_path / "Repository"
    p.mkdir()
    (p / "OBJECTS.DATA").write_bytes(S.build_objects())
    js = tmp_path / "w.json"
    csv = tmp_path / "w.csv"
    rc = main([str(p), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js.read_text())
    assert len(data) >= 4

    main([str(p), "--type", "consumer", "--json", str(js), "-q"])
    cons = json.loads(js.read_text())
    assert cons and all(r["type"] == "consumer" for r in cons)

    main([str(p), "--min-severity", "high", "--json", str(js), "-q"])
    hi = json.loads(js.read_text())
    assert hi and all(r["severity"] == "high" for r in hi)

    main([str(p), "--grep", "SecurityUpdater", "--json", str(js), "-q"])
    assert json.loads(js.read_text())


def test_csv_injection_guard():
    from windows_wmi.tracelib import sanitize
    assert sanitize("=1+1") == "'=1+1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
