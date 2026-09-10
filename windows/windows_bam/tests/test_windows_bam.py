from __future__ import annotations

import json

import pytest

from windows_bam.bam import parse
from windows_bam import flags as _flags
from windows_bam.cli import main

import _synth as S


@pytest.fixture
def system_hive(tmp_path):
    p = tmp_path / "SYSTEM"
    p.write_bytes(S.build_system_hive())
    return p


def test_parse(system_hive):
    res = parse(system_hive.read_bytes())
    assert res.sids == {S.SID_USER, S.SID_SYS}
    by_path = {e.path.rsplit("\\", 1)[-1]: e for e in res.entries}
    assert "cmd.exe" in by_path
    cmd = by_path["cmd.exe"]
    assert cmd.moderator == "bam"
    assert cmd.control_set == "ControlSet001"
    assert cmd.last_run.startswith("2026-03-06T09:00:00")
    assert cmd.path.startswith("<vol3>\\Windows\\System32\\")


def test_dam_entries(system_hive):
    res = parse(system_hive.read_bytes())
    dam = [e for e in res.entries if e.moderator == "dam"]
    assert dam and dam[0].path.endswith("App\\App.exe")


def test_flags(system_hive):
    res = parse(system_hive.read_bytes())
    for e in res.entries:
        e.notable = _flags.flag(e)
    by = {e.path.rsplit("\\", 1)[-1]: e for e in res.entries
          if e.sid == S.SID_USER}
    assert any("user-writable path" in n for n in by["agent.exe"].notable)
    assert any("living-off-the-land" in n for n in by["powershell.exe"].notable)
    # svchost.exe in \Users\victim\Downloads -> masquerade + writable path
    j = " ".join(by["svchost.exe"].notable)
    assert "system binary name" in j
    assert _flags.severity(by["svchost.exe"].notable) == "high"


def test_cli_csv_json_filters(system_hive, tmp_path):
    csv_p = tmp_path / "b.csv"
    js_p = tmp_path / "b.json"
    rc = main([str(system_hive), "--csv", str(csv_p), "--json", str(js_p),
               "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 6

    main([str(system_hive), "--moderator", "dam", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["moderator"] == "dam" for r in got)

    main([str(system_hive), "--sid", S.SID_SYS, "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["sid"] == S.SID_SYS for r in got)

    main([str(system_hive), "--min-severity", "high", "--json", str(js_p),
          "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_mounted_root(system_hive, tmp_path):
    root = tmp_path / "img"
    (root / "Windows/System32/config").mkdir(parents=True)
    (root / "Windows/System32/config/SYSTEM").write_bytes(
        system_hive.read_bytes())
    js_p = tmp_path / "b.json"
    rc = main([str(root), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 6


def test_csv_injection_guard():
    from windows_bam.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
