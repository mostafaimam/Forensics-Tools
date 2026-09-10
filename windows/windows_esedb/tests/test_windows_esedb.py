from __future__ import annotations

import json

import pytest

from windows_esedb.database import EseDatabase, EseError
from windows_esedb.cli import main

import _ese_synth as S


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "test.edb"
    p.write_bytes(S.build())
    return p


def test_header(db_path):
    db = EseDatabase.from_file(db_path)
    info = db.info()
    assert info["page_size"] == 4096
    assert info["clean"] is True
    assert info["format_version"] == "0x620"


def test_catalog(db_path):
    db = EseDatabase.from_file(db_path)
    assert "Events" in db.table_names
    t = db.table("Events")
    names = [c.name for c in t.columns]
    assert names == ["Id", "Ts", "Count", "Name", "Note"]
    idc = t.column_by_id(1)
    assert idc.name == "Id" and idc.is_fixed
    assert t.column_by_id(128).is_variable
    assert t.column_by_id(256).is_tagged


def test_records(db_path):
    db = EseDatabase.from_file(db_path)
    rows = list(db.table("Events").records())
    assert len(rows) == 3
    by_name = {r["Name"]: r for r in rows}
    assert by_name["alpha"]["Id"] == 1
    assert by_name["alpha"]["Count"] == 3
    assert by_name["alpha"]["Ts"] == "2026-03-01T08:00:00"
    assert by_name["alpha"]["Note"] == "first note"
    assert by_name["bravo"]["Note"] == "x" * 400
    assert by_name["charlie"]["Note"] in (None, "")


def test_cli_info_and_list(db_path, capsys):
    assert main([str(db_path), "--info"]) == 0
    out = capsys.readouterr().out
    assert "page_size" in out and "Events" in out

    assert main([str(db_path), "--list-tables"]) == 0
    assert "Events" in capsys.readouterr().out


def test_cli_dump_csv_json(db_path, tmp_path):
    csv_p = tmp_path / "e.csv"
    js_p = tmp_path / "e.json"
    rc = main([str(db_path), "--table", "Events", "--csv", str(csv_p),
               "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 3
    assert {r["Name"] for r in data} == {"alpha", "bravo", "charlie"}


def test_bad_file(tmp_path):
    p = tmp_path / "x.edb"
    p.write_bytes(b"not an ese db" + b"\x00" * 1000)
    with pytest.raises(EseError):
        EseDatabase.from_file(p)


def test_csv_injection_guard():
    from windows_esedb.tracelib import sanitize
    assert sanitize("=2+2") == "'=2+2"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
