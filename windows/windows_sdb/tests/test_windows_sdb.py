from __future__ import annotations

import json

import pytest

import _synth as S

from windows_sdb.sdb import Sdb
from windows_sdb.extract import extract
from windows_sdb.collect import collect
from windows_sdb.cli import main


def test_parse_tree():
    sdb = Sdb(S.build_sdb())
    recs = {r.kind: r for r in extract(sdb, "evil.sdb")}
    assert recs["database"].name == "EvilShimDB"
    assert recs["database"].guid == "aaaaaaaa-1111-2222-3333-444444444444"
    assert recs["database"].time == "2026-03-16T09:00:00Z"

    shim = recs["shim"]
    assert shim.name == "InjectDll"
    assert shim.dll == "C:\\Users\\victim\\AppData\\Local\\evil.dll"

    exe = recs["exe"]
    assert exe.name == "svchost.exe"
    assert "InjectDll" in exe.shims
    assert "EvilPatch" in exe.patches
    assert exe.matches and exe.matches[0].startswith("svchost.exe")


def test_flags(tmp_path):
    p = tmp_path / "custom.sdb"
    p.write_bytes(S.build_sdb())
    res = collect([str(p)])
    by = {}
    for r in res.rows:
        by.setdefault(r["kind"], []).append(r)

    db = by["database"][0]
    assert "custom shim database" in db["notable"]

    shim = by["shim"][0]
    assert shim["severity"] == "high"
    assert "DLL injection" in shim["notable"]
    assert "not a standard AppCompat module" in shim["notable"]

    exe = by["exe"][0]
    assert exe["severity"] == "high"
    assert "custom binary patch" in exe["notable"]
    assert "Windows system binary" in exe["notable"]

    patch = by["patch"][0]
    assert patch["severity"] == "high"


def test_system_db_quieter(tmp_path):
    p = tmp_path / "sysmain.sdb"
    p.write_bytes(S.build_benign_sdb())
    res = collect([str(p)])
    db = next(r for r in res.rows if r["kind"] == "database")
    assert "custom shim database" not in (db["notable"] or "")


def test_cli_filters(tmp_path):
    p = tmp_path / "custom.sdb"
    p.write_bytes(S.build_sdb())
    js = tmp_path / "s.json"
    csv = tmp_path / "s.csv"
    rc = main([str(p), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js.read_text())) >= 4

    main([str(p), "--kind", "shim", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["kind"] == "shim" for r in got)

    main([str(p), "--min-severity", "high", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(p), "--grep", "svchost", "--json", str(js), "-q"])
    assert json.loads(js.read_text())


def test_csv_injection_guard():
    from windows_sdb.tracelib import sanitize
    assert sanitize("-2+3") == "'-2+3"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
