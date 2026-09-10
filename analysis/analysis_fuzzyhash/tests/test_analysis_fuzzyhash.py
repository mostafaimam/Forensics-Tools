from __future__ import annotations

import json
import os
import struct

import pytest

from analysis_fuzzyhash import ctph, locality
from analysis_fuzzyhash.pehash import parse_pe
from analysis_fuzzyhash.scan import scan
from analysis_fuzzyhash.cli import main


def _text(n, seed=0):
    import random
    r = random.Random(seed)
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
             "golf", "hotel", "india", "juliet"]
    return (" ".join(r.choice(words) for _ in range(n))).encode()


def test_ctph_identical_and_similar():
    a = _text(3000, seed=1)
    b = bytearray(a)
    b[100:120] = b"XXXXXXXXXXXXXXXXXXXX"          # small edit
    ha, hb = ctph.hash_bytes(bytes(a)), ctph.hash_bytes(bytes(b))
    assert ctph.compare(ha, ha) == 100
    assert ctph.compare(ha, hb) > 50
    unrelated = ctph.hash_bytes(_text(3000, seed=99))
    assert ctph.compare(ha, unrelated) < ctph.compare(ha, hb)


def test_locality_digest():
    a = _text(8000, seed=2)
    b = bytearray(a)
    b[4000:4050] = b"Y" * 50
    da, db = locality.digest(bytes(a)), locality.digest(bytes(b))
    assert locality.similarity(da, da) == 100
    assert locality.similarity(da, db) > locality.similarity(
        da, locality.digest(_text(8000, seed=50)))


def _mini_pe(funcs):
    """A minimal PE32 whose single section maps RVA 0x1000 -> file 0x200."""
    SEC_RVA, SEC_OFF = 0x1000, 0x200
    data = bytearray(0x600)
    data[0:2] = b"MZ"
    pe = 0x80
    struct.pack_into("<I", data, 0x3C, pe)
    data[pe:pe + 4] = b"PE\x00\x00"
    struct.pack_into("<HH", data, pe + 4, 0x14C, 1)            # machine, nsec
    opt_size = 0xE0
    struct.pack_into("<H", data, pe + 4 + 16, opt_size)
    opt = pe + 4 + 20
    struct.pack_into("<H", data, opt, 0x10B)                   # PE32 magic
    dd = opt + 0x60                                            # data dirs
    imp_rva = SEC_RVA
    struct.pack_into("<II", data, dd + 8, imp_rva, 40)         # import dir
    sec = opt + opt_size
    struct.pack_into("<8s", data, sec, b".idata")
    struct.pack_into("<IIII", data, sec + 8, 0x400, SEC_RVA, 0x400, SEC_OFF)

    def put(rva, blob):
        data[SEC_OFF + (rva - SEC_RVA): SEC_OFF + (rva - SEC_RVA)
             + len(blob)] = blob

    thunk_rva = SEC_RVA + 0x40
    dllname_rva = SEC_RVA + 0x80
    names_rva = SEC_RVA + 0xC0
    # import descriptor: OriginalFirstThunk, TS, Fwd, Name, FirstThunk
    put(imp_rva, struct.pack("<IIIII", thunk_rva, 0, 0, dllname_rva,
                             thunk_rva))
    put(imp_rva + 20, b"\x00" * 20)
    put(dllname_rva, b"KERNEL32.dll\x00")
    cur = names_rva
    thunks = b""
    for fn in funcs:
        put(cur, struct.pack("<H", 0) + fn.encode() + b"\x00")
        thunks += struct.pack("<I", cur)
        cur += 2 + len(fn) + 2
    thunks += b"\x00\x00\x00\x00"
    put(thunk_rva, thunks)
    return bytes(data)


def test_imphash():
    pe = parse_pe(_mini_pe(["CreateFileA", "VirtualAlloc"]))
    assert pe["is_pe"]
    assert pe["imports"] == ["kernel32.createfilea", "kernel32.virtualalloc"]
    assert pe["imphash"]
    pe2 = parse_pe(_mini_pe(["CreateFileA", "VirtualAlloc"]))
    assert pe["imphash"] == pe2["imphash"]


def test_scan_clusters(tmp_path):
    base = _text(4000, seed=7)
    (tmp_path / "v1.txt").write_bytes(base)
    v2 = bytearray(base)
    v2[50:60] = b"ZZZZZZZZZZ"
    (tmp_path / "v2.txt").write_bytes(bytes(v2))
    v3 = bytearray(base)
    v3[200:230] = b"Q" * 30
    (tmp_path / "v3.txt").write_bytes(bytes(v3))
    import random
    (tmp_path / "other.txt").write_bytes(
        bytes(random.Random(123).randrange(256) for _ in range(20000)))

    res = scan([str(tmp_path)], threshold=70)
    clustered = {os.path.basename(p) for members in res.clusters.values()
                 for p in members}
    assert {"v1.txt", "v2.txt", "v3.txt"} <= clustered
    assert "other.txt" not in clustered
    reps = [it for it in res.items if it.representative]
    assert len(reps) == 1


def test_cli(tmp_path):
    base = _text(3000, seed=3)
    (tmp_path / "a.bin").write_bytes(base)
    b = bytearray(base)
    b[10:20] = b"..........."[:10]
    (tmp_path / "b.bin").write_bytes(bytes(b))
    js = tmp_path / "fh.json"
    csv = tmp_path / "fh.csv"
    rc = main(["scan", str(tmp_path), "--threshold", "60",
               "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert any(r["cluster"] for r in rows)

    rc = main(["compare", str(tmp_path / "a.bin"), str(tmp_path / "b.bin")])
    assert rc == 0


def test_csv_injection_guard():
    from analysis_fuzzyhash.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
