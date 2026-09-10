from __future__ import annotations

import json

import pytest

from windows_thumbcache import thumbcache as TC
from windows_thumbcache.analyze import analyze
from windows_thumbcache.cli import main

import _synth as S


@pytest.fixture
def cache_dir(tmp_path):
    d = tmp_path / "Explorer"
    d.mkdir()
    (d / "thumbcache_256.db").write_bytes(S.build_cache())
    (d / "thumbcache_idx.db").write_bytes(S.build_index())
    return d


def test_parse_cache():
    cf = TC.parse_cache(S.build_cache(), "thumbcache_256.db")
    assert cf.version_name == "Windows 8.1"
    assert len(cf.entries) == 4
    by_id = {t.cache_id: t for t in cf.entries}
    stolen = by_id[0x2222222222222222]
    assert stolen.identifier.endswith("stolen.jpg")
    assert stolen.fmt == "jpeg"
    assert stolen.width == 256 and stolen.height == 171
    assert by_id[0x3333333333333333].fmt == "png"
    assert by_id[0x4444444444444444].fmt == ""


def test_index_join(cache_dir):
    res = analyze([str(cache_dir)])
    assert res.index_entries == 4
    assert res.versions == {"Windows 8.1"}
    t = next(t for t in res.thumbnails if t.cache_id == 0x1111111111111111)
    assert t.last_modified.startswith("2026-03-08T12:00:00")


def test_flags(cache_dir):
    res = analyze([str(cache_dir)])
    by = {t.cache_id: t for t in res.thumbnails}
    assert any("user-writable path" in n
               for n in by[0x2222222222222222].notable)
    assert any("removable / network path" in n
               for n in by[0x3333333333333333].notable)
    assert any("not a recognised image format" in n
               for n in by[0x4444444444444444].notable)


def test_cli_csv_json(cache_dir, tmp_path):
    csv_p = tmp_path / "t.csv"
    js_p = tmp_path / "t.json"
    rc = main([str(cache_dir), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 4
    assert {r["cache_id"] for r in data} == {
        "1111111111111111", "2222222222222222",
        "3333333333333333", "4444444444444444"}

    main([str(cache_dir), "--format", "png", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["format"] == "png" for r in got)

    main([str(cache_dir), "--min-severity", "medium", "--json", str(js_p),
          "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "medium" for r in got)


def test_cli_extract(cache_dir, tmp_path):
    outdir = tmp_path / "thumbs"
    rc = main([str(cache_dir), "--extract", str(outdir), "-q"])
    assert rc == 0
    files = sorted(p.name for p in outdir.iterdir())
    assert "2222222222222222.jpeg" in files
    assert "3333333333333333.png" in files
    jpg = (outdir / "2222222222222222.jpeg").read_bytes()
    assert jpg[:3] == b"\xff\xd8\xff"


def test_bad_file(tmp_path):
    p = tmp_path / "x.db"
    p.write_bytes(b"NOTCMMM" + b"\x00" * 100)
    with pytest.raises(TC.ThumbError):
        TC.parse_cache(p.read_bytes())


def test_csv_injection_guard():
    from windows_thumbcache.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
