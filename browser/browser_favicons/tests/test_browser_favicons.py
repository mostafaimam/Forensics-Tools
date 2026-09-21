from __future__ import annotations

import json

import pytest

import _synth as S

from browser_favicons.collect import collect
from browser_favicons.cli import main


def test_chromium_favicons(tmp_path):
    p = tmp_path / "Favicons"
    S.build_chromium_favicons(p)
    res = collect([str(p)])
    assert not res.warnings
    a = next(r for r in res.rows if r["page_url"] == "https://a.example/page")
    assert a["icon_url"] == "https://a.example/f.ico"
    assert a["icon_type"] == "favicon"
    assert a["width"] == 16
    assert a["last_updated"].startswith("2025-")
    assert a["image_bytes"] > 0


def test_firefox_favicons(tmp_path):
    p = tmp_path / "favicons.sqlite"
    S.build_firefox_favicons(p)
    res = collect([str(p)])
    row = res.rows[0]
    assert row["browser"] == "firefox"
    assert row["page_url"] == "https://ff.example/page"
    assert row["icon_url"] == "https://ff.example/icon.png"
    assert row["last_updated"]


def test_history_cross_reference_flags_cleared(tmp_path):
    fav = tmp_path / "Favicons"
    hist = tmp_path / "History"
    S.build_chromium_favicons(fav)
    S.build_chromium_history(hist, ["https://a.example/page"])
    res = collect([str(fav)], history_path=str(hist))
    a = next(r for r in res.rows if r["page_url"] == "https://a.example/page")
    cleared = next(r for r in res.rows
                  if r["page_url"] == "https://cleared.example/gone")
    assert a["cleared_from_history"] is False
    assert cleared["cleared_from_history"] is True


def test_no_history_leaves_field_blank(tmp_path):
    fav = tmp_path / "Favicons"
    S.build_chromium_favicons(fav)
    res = collect([str(fav)])
    assert all(r["cleared_from_history"] == "" for r in res.rows)


def test_bad_history_path_warns(tmp_path):
    fav = tmp_path / "Favicons"
    S.build_chromium_favicons(fav)
    bad_hist = tmp_path / "not_a_db.sqlite"
    bad_hist.write_bytes(b"not a database")
    res = collect([str(fav)], history_path=str(bad_hist))
    assert res.warnings


def test_no_store_found_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_image_indexed_for_extraction(tmp_path):
    p = tmp_path / "Favicons"
    S.build_chromium_favicons(p)
    res = collect([str(p)])
    assert res.images
    for idx, data in res.images.items():
        assert data.startswith(b"\x89PNG")
        assert res.rows[idx]["image_bytes"] == len(data)


def test_cli_extract(tmp_path):
    p = tmp_path / "Favicons"
    S.build_chromium_favicons(p)
    out_dir = tmp_path / "icons"
    rc = main([str(p), "--extract-dir", str(out_dir), "-q"])
    assert rc == 0
    files = list(out_dir.glob("*.png"))
    assert len(files) == 2


def test_cli_csv_json(tmp_path):
    p = tmp_path / "Favicons"
    S.build_chromium_favicons(p)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows
    assert "_image_index" not in json.dumps(rows)


def test_cli_cleared_only(tmp_path):
    fav = tmp_path / "Favicons"
    hist = tmp_path / "History"
    S.build_chromium_favicons(fav)
    S.build_chromium_history(hist, ["https://a.example/page"])
    js_p = tmp_path / "out.json"
    rc = main([str(fav), "--history", str(hist), "--cleared-only",
              "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["page_url"] == "https://cleared.example/gone"
                        for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from browser_favicons.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
