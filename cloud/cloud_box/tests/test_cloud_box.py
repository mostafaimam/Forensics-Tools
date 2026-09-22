from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_box.discover import find_candidates
from cloud_box.collect import collect
from cloud_box.cli import main


def test_find_candidates_under_box_path(tmp_path):
    S.build_tree(tmp_path)
    found = {p.name for p in find_candidates(str(tmp_path))}
    assert found == {"sync_state.db", "cache.dat"}


def test_find_candidates_ignores_non_box_paths(tmp_path):
    S.build_no_box(tmp_path)
    found = find_candidates(str(tmp_path))
    assert found == []


def test_collect_dumps_sqlite_candidate(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    assert len(res.rows) == 1
    assert res.rows[0]["table"] == "synced_items"
    assert "budget.xlsx" in res.rows[0]["path_hint"]


def test_non_sqlite_candidate_does_not_block_real_data(tmp_path):
    S.build_tree(tmp_path)
    res = collect([str(tmp_path)])
    # cache.dat (random bytes, not SQLite) is silently skipped rather
    # than crashing the scan or suppressing sync_state.db's real rows
    assert res.rows
    assert not res.warnings


def test_no_box_path_warns(tmp_path):
    S.build_no_box(tmp_path)
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
    rc = main([str(tmp_path), "--table", "synced", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["table"] == "synced_items" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_box.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
