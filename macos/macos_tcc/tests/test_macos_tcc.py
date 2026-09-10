from __future__ import annotations

import json

import pytest

from macos_tcc.parse import parse
from macos_tcc import flags as _flags
from macos_tcc.cli import main

import _synth as S


def test_modern_schema(tmp_path):
    p = S.build_system(str(tmp_path / "TCC.db"))
    grants = parse(p, "system")
    assert len(grants) == 5
    by = {(g.service_raw, g.client): g for g in grants}
    fda = by[("kTCCServiceSystemPolicyAllFiles",
              "/Applications/BackupTool.app")]
    assert fda.service == "Full Disk Access"
    assert fda.decision == "allowed"
    assert fda.last_modified.startswith("2026-03-11T09:00")
    xcode = by[("kTCCServiceDeveloperTool", "com.apple.dt.Xcode")]
    assert xcode.decision == "denied"


def test_old_schema(tmp_path):
    p = S.build_old(str(tmp_path / "TCC.db"))
    grants = parse(p, "system")
    assert len(grants) == 2
    by = {g.client: g for g in grants}
    assert by["com.apple.Terminal"].decision == "allowed"
    assert by["com.example.app"].decision == "denied"


def test_flags(tmp_path):
    grants = parse(S.build_system(str(tmp_path / "TCC.db")), "system")
    by = {(g.service_raw, g.client): g for g in grants}
    term = by[("kTCCServiceScreenCapture", "com.apple.Terminal")]
    assert any("command-line / scripting tool" in n for n in term.notable)
    assert _flags.severity(term.notable) == "high"

    helper = by[("kTCCServiceAccessibility", "/usr/local/bin/helper")]
    assert any("outside /Applications" in n for n in helper.notable)

    kbd = by[("kTCCServiceListenEvent", "/Users/victim/.local/bin/kbd")]
    assert any("keystroke-capture permission granted" in n
               for n in kbd.notable)
    assert any("user-writable path" in n for n in kbd.notable)

    # Xcode is denied -> no high-impact flag
    xcode = by[("kTCCServiceDeveloperTool", "com.apple.dt.Xcode")]
    assert not xcode.notable


def test_automation_flag(tmp_path):
    grants = parse(S.build_user(str(tmp_path / "TCC.db")), "user")
    ae = next(g for g in grants
              if g.service_raw == "kTCCServiceAppleEvents")
    assert ae.indirect_object == "com.apple.systemevents"
    assert any("Automation control over com.apple.systemevents" in n
               for n in ae.notable)


def test_cli_two_dbs_mounted(tmp_path):
    vol = tmp_path / "mac"
    sysdir = vol / "Library/Application Support/com.apple.TCC"
    usrdir = vol / "Users/victim/Library/Application Support/com.apple.TCC"
    sysdir.mkdir(parents=True)
    usrdir.mkdir(parents=True)
    S.build_system(str(sysdir / "TCC.db"))
    S.build_user(str(usrdir / "TCC.db"))
    js_p = tmp_path / "t.json"
    rc = main([str(vol), "--csv", str(tmp_path / "t.csv"),
               "--json", str(js_p), "-q"])
    assert rc == 0
    assert (tmp_path / "t.csv").read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 9
    assert {"system", "user"} == {r["scope"] for r in data}

    main([str(vol), "--decision", "allowed", "--scope", "user",
          "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["decision"] == "allowed" and r["scope"] == "user"
                       for r in got)

    main([str(vol), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_csv_injection_guard():
    from macos_tcc.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
