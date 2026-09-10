from __future__ import annotations

import json

import pytest

from macos_installhistory.parse import collect
from macos_installhistory import flags as _flags
from macos_installhistory.cli import main

import _synth as S


@pytest.fixture
def vol(tmp_path):
    return S.build_volume(tmp_path / "mac")


def test_collect(vol):
    res = collect(str(vol))
    assert res.history_count == 5
    assert res.receipt_count == 3
    hist = [r for r in res.records if r.kind == "history"]
    chrome = next(r for r in hist if r.name == "Google Chrome")
    assert chrome.version == "133.0"
    assert chrome.date.startswith("2026-02-10T14:00")
    assert chrome.process == "installer"


def test_correlation(vol):
    res = collect(str(vol))
    by = {(r.kind, r.name): r for r in res.records}
    assert by[("history", "Google Chrome")].correlated is True
    dropper = next(r for r in res.records
                   if r.kind == "receipt" and r.name == "com.evil.dropper")
    assert dropper.correlated is False


def test_flags(vol):
    res = collect(str(vol))
    by_name = {}
    for r in res.records:
        by_name.setdefault(r.name, []).append(r)

    helper = by_name["SupportHelper"][0]
    assert any("shell / scripting process (bash)" in n
               for n in helper.notable)
    assert _flags.severity(helper.notable) == "high"

    dropper = next(r for r in res.records if r.name == "com.evil.dropper")
    j = " ".join(dropper.notable)
    assert "download / temp folder" in j
    assert "non-standard install prefix (/Users/victim)" in j
    assert "no matching InstallHistory entry" in j

    profile = by_name["Corp Profile"][0]
    assert any("configuration profile" in n for n in profile.notable)

    # Apple XProtect config-data: quiet
    xp = by_name["XProtectPlistConfigData"][0]
    assert not xp.notable


def test_cli_csv_json_filters(vol, tmp_path):
    csv_p = tmp_path / "i.csv"
    js_p = tmp_path / "i.json"
    rc = main([str(vol), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 8       # 5 history + 3 receipts

    main([str(vol), "--kind", "receipt", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["kind"] == "receipt" for r in got)

    main([str(vol), "--process", "bash", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["process"] == "bash" for r in got)

    main([str(vol), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_history_file_only(vol, tmp_path):
    hp = vol / "Library/Receipts/InstallHistory.plist"
    js_p = tmp_path / "i.json"
    rc = main([str(hp), "--json", str(js_p), "-q"])
    assert rc == 0
    got = json.loads(js_p.read_text())
    assert len(got) == 5 and all(r["kind"] == "history" for r in got)


def test_csv_injection_guard():
    from macos_installhistory.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
