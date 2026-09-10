from __future__ import annotations

import json
import struct

import pytest

from utilities_hex.hexview import hexdump, search
from utilities_hex.interp import interpret
from utilities_hex.cli import main


def test_hexdump():
    d = bytes(range(32))
    out = hexdump(d)
    assert out.splitlines()[0].startswith("00000000  00 01 02")
    assert "|" in out


def test_interpret_scalars():
    buf = struct.pack("<iIqf", -5, 0xDEADBEEF, 1, 3.5)
    r = interpret(buf, 0)
    assert r["int32_le"] == -5
    assert r["uint32_le"] == (-5 & 0xFFFFFFFF)
    assert r["int32_be"] != -5
    assert interpret(buf, 4)["uint32_le"] == 0xDEADBEEF
    r2 = interpret(buf, 8)
    assert r2["int64_le"] == 1
    assert abs(interpret(buf, 16)["float_le"] - 3.5) < 1e-6


def test_interpret_filetime():
    # 2026-03-16T09:00:00Z as FILETIME
    from datetime import datetime, timezone
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    target = datetime(2026, 3, 16, 9, 0, tzinfo=timezone.utc)
    ft = int((target - epoch).total_seconds() * 10_000_000)
    buf = struct.pack("<Q", ft)
    r = interpret(buf, 0)
    assert r["timestamps"]["filetime"] == "2026-03-16T09:00:00Z"


def test_interpret_guid():
    import uuid
    g = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
    r = interpret(g.bytes_le, 0)
    assert r["guid_le"] == str(g)


def test_search_text_and_hex(tmp_path):
    p = tmp_path / "d.bin"
    p.write_bytes(b"\x00" * 100 + b"MZ\x90\x00" + b"\x00" * 50 +
                  b"FILE0" + b"\x00" * 10)
    hits = list(search(str(p), "MZ", kind="text"))
    assert hits and hits[0][0] == 100
    hits2 = list(search(str(p), "46 49 4c 45 30", kind="hex"))
    assert hits2 and hits2[0][0] == 154


def test_search_boundary(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * ((8 << 20) - 3) + b"NEEDLEHERE" + b"\x00" * 40)
    hits = list(search(str(p), "NEEDLEHERE", kind="text"))
    assert hits and hits[0][0] == (8 << 20) - 3


def test_cli_dump_interpret_search(tmp_path):
    p = tmp_path / "rec.bin"
    p.write_bytes(struct.pack("<II", 7, 0xCAFEBABE) + b"payload MZ here")

    rc = main([str(p), "--offset", "0", "--length", "16", "-q"])
    assert rc == 0

    js = tmp_path / "i.json"
    main([str(p), "--at", "0", "--json", str(js), "-q"])
    info = json.loads(js.read_text())[0]
    assert info["uint32_le"] == 7

    js2 = tmp_path / "s.json"
    rc = main([str(p), "--search", "MZ", "--json", str(js2), "-q"])
    assert rc == 0
    assert json.loads(js2.read_text())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
