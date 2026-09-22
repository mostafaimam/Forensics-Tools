from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_onedrive.settings import parse_settings_file
from cloud_onedrive.genericdb import is_sqlite, dump_all_tables
from cloud_onedrive.collect import collect
from cloud_onedrive.cli import main


def test_parse_settings_file(tmp_path):
    S.build_tree(tmp_path)
    ini = (tmp_path / "Microsoft" / "OneDrive" / "settings" / "Personal" /
          "global.ini")
    kv = parse_settings_file(ini)
    assert kv["cid"] == "1234567890ABCDEF"
    assert kv["EmailAddress"] == "alice@example.com"
    assert kv["DisplayName"] == "Alice Example"


def test_is_sqlite_detection(tmp_path):
    S.build_tree(tmp_path)
    db = (tmp_path / "Microsoft" / "OneDrive" / "settings" / "Personal" /
         "SyncEngineDatabase.db")
    assert is_sqlite(db)


def test_ese_stub_not_sqlite(tmp_path):
    S.build_ese_stub(tmp_path)
    db = (tmp_path / "Microsoft" / "OneDrive" / "settings" / "Business1" /
         "SyncEngineDatabase.db")
    assert not is_sqlite(db)


def test_dump_all_tables(tmp_path):
    S.build_tree(tmp_path)
    db = (tmp_path / "Microsoft" / "OneDrive" / "settings" / "Personal" /
         "SyncEngineDatabase.db")
    tables = dump_all_tables(str(db))
    assert "items" in tables
    cols, rows = tables["items"]
    assert "Path" in cols
    assert len(rows) == 2


def test_collect_settings_and_db_rows(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    assert not res.warnings
    kinds = {r["kind"] for r in res.rows}
    assert kinds == {"setting", "db_row"}
    setting_row = next(r for r in res.rows if r["table_or_key"] == "cid")
    assert setting_row["value_or_row_json"] == "1234567890ABCDEF"


def test_collect_path_time_size_hints(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    db_rows = [r for r in res.rows if r["kind"] == "db_row"]
    report_row = next(r for r in db_rows
                      if "report.docx" in r["path_hint"])
    assert report_row["time_hint"] == "2026-01-01T00:00:00Z"
    assert report_row["size_hint"] == "40960"


def test_ese_database_warns_not_crashes(tmp_path):
    S.build_ese_stub(tmp_path)
    res = collect([str(tmp_path)])
    assert not res.rows
    assert any("esedb" in w.lower() or "ese" in w.lower()
              for w in res.warnings)


def test_no_files_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    S.build_tree(tmp_path)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p),
              "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_kind_filter(tmp_path):
    S.build_tree(tmp_path)
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--kind", "setting", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["kind"] == "setting" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_onedrive.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
