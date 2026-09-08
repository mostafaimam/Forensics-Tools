from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from browser_bookmarks import output
from browser_bookmarks.analyze import analyze
from browser_bookmarks.cli import main

import _synth as S

A = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
M = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _by_title(res):
    return {b.title: b for b in res.bookmarks}


def test_chromium_bookmarks_tree(tmp_path):
    bm = tmp_path / "Bookmarks"
    S.chromium_bookmarks(bm,
                         bar=[
                             ("GitHub", "https://github.com/", A, M),
                             S._folder("Work", [
                                 S._url_node("Jira", "https://jira.corp/", A),
                             ]),
                         ],
                         other=[("Router", "http://192.168.0.1:8081/", A)])
    res = analyze([str(bm)])
    by = _by_title(res)
    assert by["GitHub"].folder == "Bookmarks bar"
    assert by["GitHub"].date_added == "2026-03-01T12:00:00Z"
    assert by["GitHub"].date_modified == "2026-10-01T12:00:00Z"
    assert by["Jira"].folder == "Bookmarks bar/Work"
    assert any("non-standard port" in x for x in by["Router"].notable)


def test_bookmarklet_and_internal_flags(tmp_path):
    bm = tmp_path / "Bookmarks"
    S.chromium_bookmarks(bm, bar=[
        ("run", "javascript:(function(){alert(1)})()", A),
        ("settings", "chrome://settings/passwords", A),
        ("dump", "file:///C:/Users/x/secret.txt", A),
    ])
    by = _by_title(analyze([str(bm)]))
    assert any("bookmarklet" in x for x in by["run"].notable)
    assert any("browser-internal" in x for x in by["settings"].notable)
    assert any("local file" in x for x in by["dump"].notable)
    assert output.row(by["run"])["severity"] == "medium"


def test_bookmarks_bak_diff_finds_deleted(tmp_path):
    bm = tmp_path / "Bookmarks"
    S.chromium_bookmarks(
        bm,
        bar=[("Keep", "https://keep.example/", A)],
        bak_bar=[("Keep", "https://keep.example/", A),
                 ("Gone", "https://darkmarket.example/", A)])
    res = analyze([str(bm)])
    by = _by_title(res)
    assert by["Gone"].source == "bak-only"
    assert any("only present in Bookmarks.bak" in x
               for x in by["Gone"].notable)
    assert by["Keep"].source == "bookmarks"


def test_firefox_bookmarks(tmp_path):
    pl = tmp_path / "places.sqlite"
    S.firefox_bookmarks(pl, [
        {"folder": "toolbar", "title": "MDN", "url": "https://developer.mozilla.org/",
         "added": A, "modified": M},
        {"folder": "Research", "title": "Onion", "url": "http://abc.onion/",
         "added": A},
    ])
    by = _by_title(analyze([str(pl)]))
    assert by["MDN"].browser == "Firefox"
    assert by["MDN"].folder == "toolbar"
    assert by["Onion"].folder == "toolbar/Research"
    assert by["MDN"].date_added == "2026-03-01T12:00:00Z"


def test_folder_walk_and_merge(tmp_path):
    (tmp_path / "Chrome").mkdir()
    (tmp_path / "ff.default").mkdir()
    S.chromium_bookmarks(tmp_path / "Chrome" / "Bookmarks",
                         bar=[("A", "https://a.example/", A)])
    S.firefox_bookmarks(tmp_path / "ff.default" / "places.sqlite",
                        [{"folder": "toolbar", "title": "B",
                          "url": "https://b.example/", "added": A}])
    res = analyze([str(tmp_path)])
    assert res.stores == 2
    assert {b.browser for b in res.bookmarks} == {"Chrome", "Firefox"}


def test_cli_csv_json_filters(tmp_path):
    bm = tmp_path / "Bookmarks"
    S.chromium_bookmarks(bm, bar=[
        ("GitHub", "https://github.com/", A),
        ("Bank", "https://bank.example/", A),
    ], bak_bar=[
        ("GitHub", "https://github.com/", A),
        ("Bank", "https://bank.example/", A),
        ("Deleted", "https://x.example/", A),
    ])
    csv_p = tmp_path / "b.csv"
    js_p = tmp_path / "b.json"
    rc = main([str(bm), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js_p.read_text())) == 3

    main([str(bm), "--deleted-only", "--json", str(js_p), "-q"])
    only = json.loads(js_p.read_text())
    assert len(only) == 1 and only[0]["title"] == "Deleted"

    main([str(bm), "--grep", "github", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["title"] == "GitHub"


def test_csv_injection_guard():
    assert output._san("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
