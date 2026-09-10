from __future__ import annotations

import json

import pytest

from macos_launchd.collect import collect
from macos_launchd import flags as _flags
from macos_launchd.cli import main

import _synth as S


@pytest.fixture
def vol(tmp_path):
    return S.build_volume(tmp_path / "mac")


def _by_label(res):
    return {j.label: j for j in res.jobs}


def test_collect_and_scope(vol):
    res = collect(str(vol))
    assert len(res.jobs) == 6
    scopes = {j.filename: j.scope for j in res.jobs}
    assert scopes["com.apple.mDNSResponder.plist"] == "apple"
    assert scopes["com.apple.softwareupdated.helper.plist"] == "system-daemon"
    assert scopes["com.adobe.updater.plist"] == "user-agent"


def test_triggers_and_command(vol):
    j = _by_label(collect(str(vol)))["com.example.reporter"]
    assert j.command_line.startswith("/usr/bin/osascript")
    assert any("hr=9" in t for t in j.triggers)
    apple = _by_label(collect(str(vol)))["com.apple.mDNSResponder"]
    assert "at load" in apple.triggers and "keepalive" in apple.triggers
    assert not apple.notable


def test_flags(vol):
    by = _by_label(collect(str(vol)))
    upd = by["com.apple.softwareupdated.helper"]
    j = " ".join(upd.notable)
    assert "download / execute cradle" in j
    assert "Label masquerades as an Apple job" in j
    assert "stdout / stderr redirected to /tmp" in j
    assert "root daemon executes from a user-writable path" not in j  # sh path
    assert _flags.severity(upd.notable) == "high"

    agent = by["com.local.agent"]
    j = " ".join(agent.notable)
    assert "user-writable path (/Users/victim/.cache/agent)" in j
    assert "dynamic-loader variable (DYLD_INSERT_LIBRARIES)" in j
    assert "does not match the plist file name 'com.adobe.updater.plist'" in j

    rep = by["com.example.reporter"]
    assert any("AppleScript / interpreter script" in n for n in rep.notable)


def test_disabled_not_flagged_for_mismatch(vol):
    by = _by_label(collect(str(vol)))
    old = by["com.old.thing"]
    assert not any("does not match" in n for n in old.notable)


def test_cli_csv_json_filters(vol, tmp_path):
    csv_p = tmp_path / "l.csv"
    js_p = tmp_path / "l.json"
    rc = main([str(vol), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 6

    main([str(vol), "--exclude-apple", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["scope"] != "apple" for r in got)

    main([str(vol), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(vol), "--scope", "system-daemon", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["scope"] == "system-daemon" for r in got)


def test_single_plist(vol, tmp_path):
    p = vol / "Library/LaunchDaemons/com.apple.softwareupdated.helper.plist"
    js_p = tmp_path / "l.json"
    rc = main([str(p), "--json", str(js_p), "-q"])
    assert rc == 0
    got = json.loads(js_p.read_text())
    assert len(got) == 1 and got[0]["label"] == "com.apple.softwareupdated.helper"


def test_csv_injection_guard():
    from macos_launchd.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
