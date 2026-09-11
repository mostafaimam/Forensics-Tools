from __future__ import annotations

import json

import pytest

import _mem as M

from memory_filescan.loader import MemoryImage
from memory_filescan.filescan import scan
from memory_filescan.cli import main


def _write(tmp_path, builder):
    p = tmp_path / "mem.raw"
    p.write_bytes(builder.bytes())
    return p


def test_scan_basic(tmp_path):
    b = M.Builder()
    b.file_object("\\Device\\HarddiskVolume2\\Windows\\System32\\hosts")
    b.file_object("\\Device\\HarddiskVolume2\\Users\\victim\\AppData\\"
                  "Local\\Temp\\evil.exe")
    img = MemoryImage(_write(tmp_path, b))
    hits = scan(img)
    img.close()
    names = {h.name for h in hits}
    assert any(n.endswith("hosts") for n in names)
    assert any(n.endswith("evil.exe") for n in names)
    hosts = next(h for h in hits if h.name.endswith("hosts"))
    assert hosts.device == "\\Device\\HarddiskVolume2"


def test_body_offset_variants(tmp_path):
    b = M.Builder()
    b.file_object("\\Device\\HarddiskVolume2\\a.txt", body_off=8)
    b.file_object("\\Device\\HarddiskVolume2\\b.txt", body_off=16)
    img = MemoryImage(_write(tmp_path, b))
    hits = scan(img)
    img.close()
    names = {h.name for h in hits}
    assert any(n.endswith("a.txt") for n in names)
    assert any(n.endswith("b.txt") for n in names)


def test_cli(tmp_path):
    b = M.Builder()
    b.file_object("\\Device\\HarddiskVolume2\\Users\\v\\AppData\\Local\\"
                  "Temp\\payload.exe")
    b.file_object("\\Device\\HarddiskVolume2\\Windows\\explorer.exe")
    p = _write(tmp_path, b)
    js = tmp_path / "o.json"
    csv = tmp_path / "o.csv"
    rc = main([str(p), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert len(rows) == 2

    main([str(p), "--notable-only", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all("payload.exe" in r["name"] for r in got)
    assert got[0]["severity"] == "high"


def test_csv_injection_guard():
    from memory_filescan.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
