from _synth import elf_core, lime_dump, raw_dump, winkdump
from memory_image.loader import MemoryImage


def _img(tmp_path, name, blob):
    p = tmp_path / name
    p.write_bytes(blob)
    return MemoryImage(p)


def test_raw(tmp_path):
    blob = raw_dump(0x10000)
    img = _img(tmp_path, "m.raw", blob)
    assert img.fmt == "raw"
    assert img.phys_size == 0x10000
    assert img.read_physical(0x100, 16) == blob[0x100:0x110]
    img.close()


def test_lime(tmp_path):
    blob, data = lime_dump([(0x1000, 0x2000), (0x100000, 0x4000)])
    img = _img(tmp_path, "m.lime", blob)
    assert img.fmt == "lime" and len(img.runs) == 2
    assert img.read_physical(0x1000, 0x2000) == data[0x1000]
    assert img.read_physical(0x100000, 0x100) == data[0x100000][:0x100]
    # gap between the two ranges reads as zeros
    assert img.read_physical(0x3000, 0x10) == b"\x00" * 0x10
    img.close()


def test_elf_core(tmp_path):
    blob, data = elf_core([(0x0, 0x1000), (0x8000, 0x2000)])
    img = _img(tmp_path, "core", blob)
    assert img.fmt == "elf" and len(img.runs) == 2
    assert img.read_physical(0x8000, 0x2000) == data[0x8000]
    img.close()


def test_winkdump(tmp_path):
    blob, data = winkdump([(0x1, 0x4), (0x100, 0x8)], dtb=0x1aa000)
    img = _img(tmp_path, "MEMORY.DMP", blob)
    assert img.fmt == "winkdump"
    assert img.os_hints["os"] == "windows" and img.os_hints["arch"] == "x64"
    assert img.os_hints["directory_table_base"] == 0x1aa000
    assert img.os_hints["dump_type"] == "full"
    assert img.read_physical(0x1000, 0x4000) == data[0x1000]
    assert img.read_physical(0x100000, 0x8000) == data[0x100000]
    img.close()


def test_read_spanning_runs_and_holes(tmp_path):
    blob, data = lime_dump([(0x0, 0x1000), (0x2000, 0x1000)])
    img = _img(tmp_path, "m.lime", blob)
    got = img.read_physical(0x800, 0x2000)      # end of r0, hole, start of r1
    assert got[:0x800] == data[0x0][0x800:]
    assert got[0x800:0x1800] == b"\x00" * 0x1000
    assert got[0x1800:] == data[0x2000][:0x800]
    img.close()


def test_os_hint_linux_banner(tmp_path):
    banner = b"Linux version 6.1.0-18-amd64 (debian@x) (gcc 12) #1 SMP\x00"
    blob = raw_dump(0x2000) + banner + raw_dump(0x1000)
    img = _img(tmp_path, "m.raw", blob)
    hints = img.scan_os_hints()
    assert hints["os"] == "linux" and hints["kernel"].startswith("6.1.0")
    img.close()
