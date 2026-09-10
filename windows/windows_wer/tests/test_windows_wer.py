from __future__ import annotations

import json

import pytest

import _synth as S

from windows_wer.parse import parse_wer
from windows_wer.collect import collect
from windows_wer.cli import main


def test_parse_crash():
    r = parse_wer(S.utf16(S.CRASH_EVIL), "Report.wer")
    assert r.event_type == "APPCRASH"
    assert r.app_name == "svch0st.exe"
    assert r.app_path.endswith("\\Temp\\svch0st.exe")
    assert r.mod_name == "vbscript.dll"
    assert r.mod_path.endswith("vbscript.dll")
    assert r.exception_code == "c0000005"
    assert r.exception_offset == "0002a1b2"
    assert r.event_time.startswith("202")
    assert r.os_version.startswith("10.0.19045")
    assert len(r.loaded_modules) == 3


def test_flags(tmp_path):
    S.write_store(tmp_path / "WER")
    res = collect([str(tmp_path)])
    by = {r["app_name"]: r for r in res.rows}

    evil = by["svch0st.exe"]
    assert evil["severity"] == "high"
    j = evil["notable"]
    assert "user-writable directory" in j
    assert "APPCRASH report" in j

    bex = by["reader.exe"]
    assert "buffer-overflow / DEP violation" in bex["notable"]
    assert "stack buffer overrun" in bex["notable"]

    benign = by["explorer.exe"]
    assert benign["severity"] == "low"


def test_cli_filters(tmp_path):
    S.write_store(tmp_path / "WER")
    js = tmp_path / "w.json"
    csv = tmp_path / "w.csv"
    rc = main([str(tmp_path), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js.read_text())) == 3

    main([str(tmp_path), "--event-type", "BEX64", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["event_type"] == "BEX64" for r in got)

    main([str(tmp_path), "--min-severity", "high", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(tmp_path), "--grep", r"Temp", "--json", str(js), "-q"])
    assert json.loads(js.read_text())


def test_csv_injection_guard():
    from windows_wer.tracelib import sanitize
    assert sanitize("@SUM(1)") == "'@SUM(1)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
