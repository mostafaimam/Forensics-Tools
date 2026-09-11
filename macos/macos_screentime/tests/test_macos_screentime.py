from __future__ import annotations

import json

import pytest

import _synth as S

from macos_screentime.screentime import analyze, dump_entity
from macos_screentime.collect import collect
from macos_screentime.cli import main


def test_entity_discovery(tmp_path):
    p = tmp_path / "RMAdminStore-Local.sqlite"
    S.build(p)
    r = analyze(str(p))
    assert set(r.usage_entities) == {"RMDAppUsage"}
    assert ("RMDDevice", "ZRMDDEVICE") in r.entities_seen


def test_usage_rows(tmp_path):
    p = tmp_path / "RMAdminStore-Local.sqlite"
    S.build(p)
    r = analyze(str(p))
    rows = {u.app: u for u in r.rows}
    assert rows["com.apple.mobilesafari"].duration_s == 7200.0
    assert rows["com.apple.mobilesafari"].date == "2026-03-15T00:00:00Z"
    assert rows["com.some.game"].device == "ipad-def"


def test_dump_entity(tmp_path):
    p = tmp_path / "RMAdminStore-Local.sqlite"
    S.build(p)
    rows = dump_entity(str(p), "RMDDevice")
    assert len(rows) == 1
    assert rows[0]["ZNAME"] == "Mostafa's iPhone"


def test_collect(tmp_path):
    S.build(tmp_path / "RMAdminStore-Local.sqlite")
    res = collect([str(tmp_path)])
    assert res.stores == 1
    assert len(res.rows) == 2


def test_cli(tmp_path):
    S.build(tmp_path / "RMAdminStore-Local.sqlite")
    js = tmp_path / "o.json"
    csv = tmp_path / "o.csv"
    rc = main([str(tmp_path), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert len(rows) == 2

    main([str(tmp_path), "--min-hours", "5", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and got[0]["app"] == "com.some.game"

    main([str(tmp_path), "--app", "safari", "--json", str(js), "-q"])
    got2 = json.loads(js.read_text())
    assert got2 and got2[0]["app"] == "com.apple.mobilesafari"


def test_list_entities(tmp_path, capsys):
    p = tmp_path / "RMAdminStore-Local.sqlite"
    S.build(p)
    rc = main([str(p), "--list-entities"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "RMDAppUsage" in out and "usage-shaped" in out


def test_csv_injection_guard():
    from macos_screentime.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
