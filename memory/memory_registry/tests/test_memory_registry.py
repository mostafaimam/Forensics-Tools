from __future__ import annotations

import json

import pytest

import _hive_synth as S

from memory_registry.loader import MemoryImage
from memory_registry.hivescan import scan
from memory_registry.cli import main


def _write(tmp_path, name="mem.raw"):
    p = tmp_path / name
    p.write_bytes(S.build_image())
    return p


def test_scan(tmp_path):
    img = MemoryImage(_write(tmp_path))
    hives = scan(img)
    img.close()
    names = {h.file_name for h in hives}
    assert any("NTUSER.DAT" in n for n in names)
    assert any(n.endswith("SYSTEM") for n in names)
    sysh = next(h for h in hives if h.file_name.endswith("SYSTEM"))
    assert sysh.dirty
    ntu = next(h for h in hives if "NTUSER" in h.file_name)
    assert not ntu.dirty
    assert ntu.last_written == "2026-03-16T09:00:00Z"


def test_cli(tmp_path):
    p = _write(tmp_path)
    js = tmp_path / "o.json"
    csv = tmp_path / "o.csv"
    rc = main([str(p), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert len(rows) == 2

    main([str(p), "--dirty-only", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["dirty"] == "yes" for r in got)

    main([str(p), "--name", "NTUSER", "--json", str(js), "-q"])
    got2 = json.loads(js.read_text())
    assert got2 and "NTUSER" in got2[0]["file_name"]


def test_csv_injection_guard():
    from memory_registry.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
