from __future__ import annotations

import json

import pytest

import _synth as S

from windows_recentfilecache.parse import parse
from windows_recentfilecache.collect import collect
from windows_recentfilecache.cli import main


def test_parse():
    p = parse(S.build_bcf())
    assert p.header_ok
    assert [e.name for e in p.entries] == [
        "iexplore.exe", "notepad.exe", "update.exe", "invoice.pdf.exe",
        "a.scr", "rundll32.exe"]
    assert p.entries[0].index == 0
    assert p.trailing_bytes == 0


def test_flags(tmp_path):
    f = tmp_path / "RecentFileCache.bcf"
    f.write_bytes(S.build_bcf())
    res = collect([str(f)])
    by = {r["name"]: r for r in res.rows}

    assert by["update.exe"]["severity"] == "high"
    assert "user-writable directory" in by["update.exe"]["notable"]

    assert "double extension" in by["invoice.pdf.exe"]["notable"]
    assert by["invoice.pdf.exe"]["severity"] == "high"

    assert "script / non-PE" in by["a.scr"]["notable"]
    assert "living-off-the-land" in by["rundll32.exe"]["notable"]

    assert by["notepad.exe"]["severity"] == "none"
    assert by["notepad.exe"]["file_mtime"].startswith("20")


def test_cli(tmp_path):
    d = tmp_path / "Programs"
    d.mkdir()
    (d / "RecentFileCache.bcf").write_bytes(S.build_bcf())
    js = tmp_path / "r.json"
    csv = tmp_path / "r.csv"
    rc = main([str(d), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js.read_text())) == 6

    main([str(d), "--min-severity", "high", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(d), "--grep", r"Temp", "--json", str(js), "-q"])
    assert json.loads(js.read_text())


def test_csv_injection_guard():
    from windows_recentfilecache.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
