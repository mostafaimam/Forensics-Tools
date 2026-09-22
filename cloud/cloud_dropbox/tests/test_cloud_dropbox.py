from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_dropbox.discover import find_db_files
from cloud_dropbox.genericdb import is_sqlite
from cloud_dropbox.collect import collect
from cloud_dropbox.cli import main


def test_find_db_files(tmp_path):
    S.build_tree(tmp_path)
    found = {p.name for p in find_db_files(str(tmp_path))}
    assert found == {"config.dbx", "filecache.dbx", "deleted.dbx"}


def test_config_dbx_is_sqlite(tmp_path):
    S.build_tree(tmp_path)
    p = tmp_path / "Dropbox" / "instance1" / "config.dbx"
    assert is_sqlite(p)


def test_deleted_dbx_not_sqlite(tmp_path):
    S.build_tree(tmp_path)
    p = tmp_path / "Dropbox" / "instance1" / "deleted.dbx"
    assert not is_sqlite(p)


def test_collect_dumps_plain_tables(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    tables = {r["table"] for r in res.rows}
    assert tables == {"config", "file_journal"}
    email_row = next(r for r in res.rows if "alice@example.com"
                     in r["row_json"])
    assert email_row["table"] == "config"


def test_collect_hints_extracted(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    journal_row = next(r for r in res.rows if r["table"] == "file_journal")
    assert "report.docx" in journal_row["path_hint"]
    assert journal_row["size_hint"] == "40960"


def test_encrypted_dbx_warns(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    assert any("encrypt" in w.lower() for w in res.warnings)


def test_no_dropbox_files_warns(tmp_path):
    S.build_no_dropbox(tmp_path)
    res = collect([str(tmp_path)])
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


def test_cli_table_filter(tmp_path):
    S.build_tree(tmp_path)
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--table", "config", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["table"] == "config" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_dropbox.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
