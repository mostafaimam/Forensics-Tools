import hashlib
import json
import os
import struct

from _synth import DATA_START, PAGE_OFFSET, make_iomem, make_kcore, phys_ram
from acquisition_ram import lime
from acquisition_ram.linux import capture, parse_elf_segments, parse_iomem, probe


def test_parse_iomem_top_level_only():
    text = make_iomem([(0x1000, 0x9000), (0x100000, 0x800000)])
    got = parse_iomem(text)
    assert got == [(0x1000, 0x9000), (0x100000, 0x800000)]


def test_parse_elf_segments():
    blob = make_kcore(phys_ram(0x2000))
    segs = parse_elf_segments(blob[:64], lambda o, n: blob[o:o + n])
    assert len(segs) == 1
    assert segs[0].p_vaddr == PAGE_OFFSET
    assert segs[0].p_offset == DATA_START


def _setup(tmp_path, ranges):
    ram = phys_ram(0x40000)
    (tmp_path / "kcore").write_bytes(make_kcore(ram))
    (tmp_path / "iomem").write_text(make_iomem(ranges))
    return ram


def test_probe_ok(tmp_path):
    _setup(tmp_path, [(0x1000, 0x20000)])
    pr = probe(str(tmp_path / "kcore"), str(tmp_path / "iomem"))
    assert pr.ok
    assert pr.page_offset == PAGE_OFFSET
    assert pr.total_ram == 0x20000 - 0x1000


def test_capture_lime_roundtrip(tmp_path):
    ram = _setup(tmp_path, [(0x1000, 0x8000), (0x10000, 0x30000)])
    pr = probe(str(tmp_path / "kcore"), str(tmp_path / "iomem"))
    out = tmp_path / "mem.lime"
    hs = {"sha256": hashlib.sha256()}
    ranges, written, warns = capture(pr, str(out), "lime", hashers=hs)

    with out.open("rb") as fh:
        parsed = lime.parse_headers(fh)
        assert [(r.start, r.end) for r in parsed] == [(0x1000, 0x8000),
                                                      (0x10000, 0x30000)]
        fh.seek(parsed[0].data_offset)
        assert fh.read(parsed[0].size) == ram[0x1000:0x8000]
        fh.seek(parsed[1].data_offset)
        assert fh.read(parsed[1].size) == ram[0x10000:0x30000]
    assert hs["sha256"].hexdigest() == \
        hashlib.sha256(out.read_bytes()).hexdigest()
    assert written == out.stat().st_size


def test_capture_raw_is_compact(tmp_path):
    ram = _setup(tmp_path, [(0x1000, 0x8000), (0x10000, 0x14000)])
    pr = probe(str(tmp_path / "kcore"), str(tmp_path / "iomem"))
    out = tmp_path / "mem.raw"
    capture(pr, str(out), "raw")
    assert out.read_bytes() == ram[0x1000:0x8000] + ram[0x10000:0x14000]


def test_capture_padded_has_physical_offsets(tmp_path):
    ram = _setup(tmp_path, [(0x1000, 0x3000), (0x8000, 0xa000)])
    pr = probe(str(tmp_path / "kcore"), str(tmp_path / "iomem"))
    out = tmp_path / "mem.padded"
    capture(pr, str(out), "padded")
    blob = out.read_bytes()
    assert blob[0x1000:0x3000] == ram[0x1000:0x3000]
    assert blob[0x8000:0xa000] == ram[0x8000:0xa000]
    assert blob[0x3000:0x8000] == b"\x00" * 0x5000       # hole
