import struct

from _synth import make_gpt_disk, make_mbr_disk
from mounting_image.formats import open_image
from mounting_image.formats.vhd import VHDImage
from mounting_image.partitions import detect
from mounting_image.vhdwrite import write_fixed_vhd


def test_fixed_vhd_roundtrip(tmp_path):
    raw = make_mbr_disk()
    src = tmp_path / "disk.raw"
    src.write_bytes(raw)
    vhd = write_fixed_vhd(open_image(str(src)), tmp_path / "out.vhd")

    v = VHDImage(str(vhd))
    assert v.disk_type == 2                       # fixed
    assert v.size == len(raw)
    assert b"".join(v.stream()) == raw
    v.close()


def test_vhd_footer_checksum_is_ones_complement(tmp_path):
    src = tmp_path / "d.raw"
    src.write_bytes(make_mbr_disk(size=4 * 1024 * 1024))
    vhd = write_fixed_vhd(open_image(str(src)), tmp_path / "o.vhd")
    footer = vhd.read_bytes()[-512:]
    stored = struct.unpack_from(">I", footer, 64)[0]
    zeroed = bytearray(footer)
    zeroed[64:68] = b"\x00\x00\x00\x00"
    assert stored == (~sum(zeroed)) & 0xFFFFFFFF
    assert footer[:8] == b"conectix"


def test_partitions_visible_through_vhd(tmp_path):
    src = tmp_path / "g.raw"
    src.write_bytes(make_gpt_disk())
    vhd = write_fixed_vhd(open_image(str(src)), tmp_path / "g.vhd")
    with VHDImage(str(vhd)) as v:
        scheme, parts = detect(v)
    assert scheme == "gpt" and len(parts) == 2
    assert parts[1].type_label == "EFI System"


def test_non_sector_aligned_source_padded(tmp_path):
    src = tmp_path / "odd.raw"
    src.write_bytes(b"\xaa" * (4096 + 100))
    vhd = write_fixed_vhd(open_image(str(src)), tmp_path / "odd.vhd")
    v = VHDImage(str(vhd))
    assert v.size % 512 == 0 and v.size == 4096 + 512
    v.close()
