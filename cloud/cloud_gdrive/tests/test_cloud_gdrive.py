from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_gdrive.discover import find_db_files
from cloud_gdrive.collect import collect
from cloud_gdrive.cli import main


def test_find_db_files(tmp_path):
    S.build_tree(tmp_path)
    found = {p.name for p in find_db_files(str(tmp_path))}
    assert found == {"metadata_sqlite_db"}


def test_collect_dumps_items(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    assert not res.warnings
    assert len(res.rows) == 2
    assert all(r["table"] == "items" for r in res.rows)


def test_collect_hints(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    row = next(r for r in res.rows if "quarterly-report" in r["path_hint"])
    assert row["size_hint"] == "102400"


def test_trashed_item_present_in_row_json(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    row = next(r for r in res.rows if "old-draft" in r["path_hint"])
    assert '"trashed": 1' in row["row_json"]


def test_no_gdrive_files_warns(tmp_path):
    S.build_no_gdrive(tmp_path)
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
    assert len(rows) == 2


def test_cli_table_filter(tmp_path):
    S.build_tree(tmp_path)
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--table", "items", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["table"] == "items" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_gdrive.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
