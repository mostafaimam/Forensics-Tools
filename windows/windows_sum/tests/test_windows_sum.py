from __future__ import annotations

import json

import pytest

import _synth as S

from windows_sum.analyze import analyze
from windows_sum import flags
from windows_sum.cli import main


def _store(tmp_path):
    d = tmp_path / "SUM"
    d.mkdir()
    (d / "SystemIdentity.mdb").write_bytes(S.build_identity())
    (d / "Current.mdb").write_bytes(S.build_current())
    return d


def test_analyze(tmp_path):
    res = analyze([str(_store(tmp_path))])
    assert res.roles["10A9226F-50EE-49D8-A393-9A501D47CE04"] == "File Server"
    by = {a.user: a for a in res.rows}
    fs = by["CORP\\jsmith"]
    assert fs.role_name == "File Server"
    assert fs.address == "10.0.0.25"
    assert fs.total_accesses == 42
    assert "2026-03-16:12" in fs.daily

    rds = by["CORP\\administrator"]
    assert rds.role_name == "Remote Desktop Services"
    assert rds.address == "45.9.148.20"


def test_flags(tmp_path):
    res = analyze([str(_store(tmp_path))])
    by = {a.user: a for a in res.rows}

    n_rds, s_rds = flags.classify(by["CORP\\administrator"])
    assert s_rds == "high"
    assert "RDP-role access from a public IP" in n_rds
    assert "access from a public IP address" in n_rds
    assert "privileged / built-in account" in n_rds
    assert any("high single-day access count" in x for x in n_rds)

    n_fs, s_fs = flags.classify(by["CORP\\jsmith"])
    assert s_fs in ("none", "low")


def test_cli_filters(tmp_path):
    d = _store(tmp_path)
    js = tmp_path / "s.json"
    csv = tmp_path / "s.csv"
    rc = main([str(d), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js.read_text())
    assert len(data) == 2

    main([str(d), "--role", "remote desktop", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all("Remote Desktop" in r["role"] for r in got)

    main([str(d), "--min-severity", "high", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(d), "--user", "jsmith", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and got[0]["user"] == "CORP\\jsmith"


def test_csv_injection_guard():
    from windows_sum.tracelib import sanitize
    assert sanitize("+1") == "'+1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
