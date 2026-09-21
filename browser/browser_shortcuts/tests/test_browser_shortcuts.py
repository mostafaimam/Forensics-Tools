from __future__ import annotations

import json

import pytest

import _synth as S

from browser_shortcuts.collect import collect
from browser_shortcuts.cli import main


def test_collect_all_kinds(tmp_path):
    profile = S.build_profile(tmp_path)
    res = collect([str(profile)])
    kinds = {r["kind"] for r in res.rows}
    assert kinds == {"shortcuts", "top_sites", "predictor"}
    assert not res.warnings


def test_shortcuts_fields(tmp_path):
    from browser_shortcuts.timeconv import chrome
    profile = S.build_profile(tmp_path)
    res = collect([str(profile)])
    gmail = next(r for r in res.rows
                if r["kind"] == "shortcuts" and r["text"] == "gmail")
    assert gmail["url"] == "https://mail.google.com/"
    assert gmail["hits"] == 42
    assert gmail["last_access"] == chrome(S._CHROME_EPOCH_SAMPLE)


def test_ip_literal_shortcut_flagged(tmp_path):
    profile = S.build_profile(tmp_path)
    res = collect([str(profile)])
    ip_row = next(r for r in res.rows if r["text"] == "192.168.1.1")
    assert ip_row["notable"] == "ip-literal-host"


def test_bookmarklet_top_site_flagged(tmp_path):
    profile = S.build_profile(tmp_path)
    res = collect([str(profile)])
    js_row = next(r for r in res.rows if "javascript" in r["url"])
    assert js_row["kind"] == "top_sites"
    assert js_row["notable"] == "bookmarklet"


def test_predictor_hit_rate(tmp_path):
    profile = S.build_profile(tmp_path)
    res = collect([str(profile)])
    pred = next(r for r in res.rows if r["kind"] == "predictor")
    assert pred["hits"] == 9 and pred["misses"] == 1
    assert pred["hit_rate"] == 0.9


def test_single_file_target(tmp_path):
    profile = S.build_profile(tmp_path)
    res = collect([str(profile / "Shortcuts")])
    assert res.rows and all(r["kind"] == "shortcuts" for r in res.rows)


def test_no_store_found_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    profile = S.build_profile(tmp_path)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(profile), "--csv", str(csv_p), "--json", str(js_p),
              "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_notable_only(tmp_path):
    profile = S.build_profile(tmp_path)
    rc = main([str(profile), "--notable-only", "-q"])
    assert rc == 0


def test_cli_kind_filter(tmp_path):
    profile = S.build_profile(tmp_path)
    js_p = tmp_path / "out.json"
    rc = main([str(profile), "--kind", "top_sites", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["kind"] == "top_sites" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from browser_shortcuts.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
