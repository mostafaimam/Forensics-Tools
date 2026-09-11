from __future__ import annotations

import json

import pytest

from macos_spotlight.carve import find_stores, iter_strings, scan_file
from macos_spotlight.collect import collect
from macos_spotlight.cli import main


def _blob(tmp_path):
    # Real store.db files isolate these identifier strings with binary
    # structure bytes (length prefixes, dictionary IDs), not English prose -
    # so each one here sits alone between null-byte separators, matching
    # how carve() actually finds them: a printable run bounded by
    # non-printable bytes on either side.
    parts = [
        b"kMDItemWhereFroms\x00",
        b"https://cdn.example.com/installers/app-1.2.3.dmg?ref=x\x00",
        "public.mpeg-4".encode("utf-16-le"),
        b"com.adobe.pdf\x00",
        b"com.corp.internal.buildtool\x00",
        b"/Users/victim/Downloads/app-1.2.3.dmg\x00",
        b"random filler text of no interest\x00",
    ]
    p = tmp_path / "store.db"
    p.write_bytes(b"\x00\x00".join(parts))
    return p


def test_extract_and_classify(tmp_path):
    p = _blob(tmp_path)
    hits = list(scan_file(str(p), str(p), min_len=6))
    cats = {h.category for h in hits}
    assert "kmditem" in cats
    assert "url" in cats
    assert "uti" in cats
    assert "bundle_id" in cats
    assert "path" in cats
    urls = [h.text for h in hits if h.category == "url"]
    assert any("app-1.2.3.dmg" in u for u in urls)
    utis = [h.text for h in hits if h.category == "uti"]
    assert "public.mpeg-4" in utis or "com.adobe.pdf" in utis


def test_encoding_coverage(tmp_path):
    p = _blob(tmp_path)
    hits = list(iter_strings(str(p), min_len=6,
                             encodings=("ascii", "utf-16le")))
    encs = {enc for _off, enc, _text in hits}
    assert "ascii" in encs
    assert "utf-16le" in encs


def test_category_filter(tmp_path):
    p = _blob(tmp_path)
    hits = list(scan_file(str(p), str(p), min_len=6, categories=["url"]))
    assert hits and all(h.category == "url" for h in hits)


def test_find_stores_in_directory(tmp_path):
    root = tmp_path / "Volume" / ".Spotlight-V100" / "Store-V2" / "ABCD1234"
    root.mkdir(parents=True)
    store = root / "store.db"
    store.write_bytes(b"kMDItemFSName\x00")
    other = root / "reverseDirectoryStore"
    other.write_bytes(b"noise\x00")
    found = find_stores(str(tmp_path / "Volume"))
    assert store in found
    assert other not in found


def test_collect_multiple_targets(tmp_path):
    p1 = _blob(tmp_path)
    root = tmp_path / "vol2" / ".Spotlight-V100" / "Store-V2" / "XYZ"
    root.mkdir(parents=True)
    p2 = root / "store.db"
    p2.write_bytes(b"kMDItemContentType image plist here\x00")
    res = collect([str(p1), str(tmp_path / "vol2")], min_len=6)
    assert len(res.sources) == 2
    assert res.rows
    assert not res.warnings


def test_collect_missing_store_warns(tmp_path):
    empty = tmp_path / "empty_dir"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    p = _blob(tmp_path)
    csv_p = tmp_path / "hits.csv"
    js_p = tmp_path / "hits.json"
    rc = main([str(p), "--min-len", "6", "--category", "url,kmditem",
              "--csv", str(csv_p), "--json", str(js_p), "-q", "--hex"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows and all(r["category"] in ("url", "kmditem") for r in rows)
    assert all(str(r["offset"]).startswith("0x") for r in rows)


def test_cli_list_categories(capsys):
    rc = main(["--list-categories"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "kmditem" in out and "url" in out


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path/store.db"])
    assert rc == 2


def test_csv_injection_guard():
    from macos_spotlight.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
