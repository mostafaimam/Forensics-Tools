from __future__ import annotations

import json

import pytest

import _synth as S

from windows_sqlmap.discover import find, is_sqlite
from windows_sqlmap.maps import builtin_maps
from windows_sqlmap.analyze import scan
from windows_sqlmap.cli import main


def test_discover(tmp_path):
    S.build_skype(tmp_path / "main.db")
    (tmp_path / "notes.txt").write_text("not a database")
    dbs = find([str(tmp_path)])
    names = {p.name for p in dbs}
    assert "main.db" in names
    assert "notes.txt" not in names
    assert is_sqlite(tmp_path / "main.db")


def test_skype_map(tmp_path):
    p = tmp_path / "main.db"
    S.build_skype(p)
    res = scan([p], builtin_maps())
    assert res.hits and res.hits[0].map_name == "skype_main"
    rows = res.hits[0].rows
    assert len(rows) == 2
    assert rows[0]["author"] == "alice"
    assert rows[0]["timestamp"] == "2026-03-16T09:00:00Z"
    assert "call" in rows[0]["body"]


def test_sticky_notes_map(tmp_path):
    p = tmp_path / "plum.sqlite"
    S.build_sticky_notes(p)
    res = scan([p], builtin_maps())
    assert res.hits and res.hits[0].map_name == "sticky_notes"
    r = res.hits[0].rows[0]
    assert "rotate the API keys" in r["text"]
    assert r["last_modified"] == "2026-03-16T09:30:00Z"


def test_unmatched_recon(tmp_path):
    p = tmp_path / "widget.db"
    S.build_unknown(p)
    res = scan([p], builtin_maps())
    assert not res.hits
    assert res.recon and res.recon[0].tables == [("WidgetSettings", 2)]


def test_custom_map_dir(tmp_path):
    p = tmp_path / "widget.db"
    S.build_unknown(p)
    mapdir = tmp_path / "maps"
    mapdir.mkdir()
    (mapdir / "widget.json").write_text(json.dumps({
        "name": "widget_settings",
        "match_tables": ["WidgetSettings"],
        "query": "SELECT key, value FROM WidgetSettings",
        "columns": ["setting", "value"],
    }))
    from windows_sqlmap.maps import load_map_dir
    maps = load_map_dir(str(mapdir))
    res = scan([p], maps)
    assert res.hits and res.hits[0].map_name == "widget_settings"
    assert {r["setting"] for r in res.hits[0].rows} == {"theme", "autosave"}


def test_cli(tmp_path):
    S.build_skype(tmp_path / "main.db")
    S.build_unknown(tmp_path / "widget.db")
    js = tmp_path / "o.json"
    csv = tmp_path / "o.csv"
    rc = main([str(tmp_path), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert any(r["_map"] == "skype_main" for r in rows)

    rc = main([str(tmp_path / "widget.db"), "--dump-table", "WidgetSettings",
               "--json", str(js), "-q"])
    assert rc == 0
    dumped = json.loads(js.read_text())
    assert any(r["_map"].startswith("dump:") for r in dumped)


def test_list_maps(capsys):
    rc = main(["--list-maps"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "skype_main" in out and "sticky_notes" in out


def test_csv_injection_guard():
    from windows_sqlmap.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
