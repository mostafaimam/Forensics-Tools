from __future__ import annotations

import json

import pytest

import _mem as M

from memory_handles.loader import MemoryImage
from memory_handles.handles import enumerate_file_handles
from memory_handles.cli import main


def _write(tmp_path, builder):
    p = tmp_path / "mem.raw"
    p.write_bytes(builder.bytes())
    return p


def test_enumerate_file_handles(tmp_path):
    b = M.Builder()
    b.plant_file_handle("\\Device\\HarddiskVolume2\\Users\\v\\secret.docx")
    img = MemoryImage(_write(tmp_path, b))
    handles = enumerate_file_handles(img)
    img.close()
    assert len(handles) == 1
    h = handles[0]
    assert h.name.endswith("secret.docx")
    assert h.pid == 0            # the minimal synthetic Proc has no PID


def test_other_shift_layouts(tmp_path):
    for shift in (19, 16):
        b = M.Builder()
        b.plant_file_handle(
            "\\Device\\HarddiskVolume2\\shifted.txt", shift=shift)
        img = MemoryImage(_write(tmp_path, b))
        handles = enumerate_file_handles(img)
        img.close()
        assert any(h.name.endswith("shifted.txt") for h in handles)


def test_cli(tmp_path):
    b = M.Builder()
    b.plant_file_handle(
        "\\Device\\HarddiskVolume2\\Users\\v\\AppData\\Local\\Temp\\x.exe")
    p = _write(tmp_path, b)
    js = tmp_path / "o.json"
    csv = tmp_path / "o.csv"
    rc = main([str(p), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert len(rows) == 1
    assert rows[0]["severity"] == "medium"
    assert "writable" in rows[0]["notable"]


def test_csv_injection_guard():
    from memory_handles.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
