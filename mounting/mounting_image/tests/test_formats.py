import pytest

from _synth import (
    make_e01,
    make_gpt_disk,
    make_mbr_disk,
    make_vhd_dynamic,
    make_vhd_fixed,
    make_vmdk_sparse,
)
from mounting_image.formats import open_image, sniff
from mounting_image.partitions import detect


def _roundtrip(tmp_path, name, blob, raw):
    p = tmp_path / name
    p.write_bytes(blob)
    with open_image(p) as img:
        assert img.size == len(raw)
        assert img.read(0, 512) == raw[:512]
        # a spot in the middle and near the end
        assert img.read(1 << 20, 4096) == raw[1 << 20:(1 << 20) + 4096]
        assert img.read(len(raw) - 256, 256) == raw[-256:]
        # whole-image stream matches
        assert b"".join(img.stream()) == raw
    return p


def test_raw_roundtrip(tmp_path):
    raw = make_mbr_disk()
    p = _roundtrip(tmp_path, "disk.raw", raw, raw)
    assert sniff(p) == "raw"


def test_split_raw(tmp_path):
    raw = make_mbr_disk()
    half = len(raw) // 2
    (tmp_path / "d.001").write_bytes(raw[:half])
    (tmp_path / "d.002").write_bytes(raw[half:])
    with open_image(tmp_path / "d.001") as img:
        assert img.segment_count == 2
        assert b"".join(img.stream()) == raw


def test_vhd_fixed(tmp_path):
    raw = make_mbr_disk()
    _roundtrip(tmp_path, "d.vhd", make_vhd_fixed(raw), raw)


def test_vhd_dynamic(tmp_path):
    raw = make_mbr_disk()
    p = _roundtrip(tmp_path, "d.vhd", make_vhd_dynamic(raw), raw)
    assert sniff(p) == "vhd"


def test_vmdk_sparse(tmp_path):
    raw = make_mbr_disk()
    p = _roundtrip(tmp_path, "d.vmdk", make_vmdk_sparse(raw), raw)
    assert sniff(p) == "vmdk"


def test_e01(tmp_path):
    raw = make_mbr_disk()
    p = _roundtrip(tmp_path, "d.E01", make_e01(raw), raw)
    assert sniff(p) == "ewf"


def test_e01_header2_metadata_utf16(tmp_path):
    raw = make_mbr_disk()
    meta = {"case_number": "2026-014", "examiner": "A. Analyst",
            "description": "SanDisk Ultra 64GB", "evidence_number": "USB-3"}
    p = tmp_path / "meta.E01"
    p.write_bytes(make_e01(raw, meta=meta))
    with open_image(p) as img:
        assert img.metadata["case_number"] == "2026-014"
        assert img.metadata["examiner"] == "A. Analyst"
        assert img.metadata["description"] == "SanDisk Ultra 64GB"
        assert img.metadata["evidence_number"] == "USB-3"


def test_mbr_partitions(tmp_path):
    raw = make_mbr_disk()
    p = tmp_path / "d.raw"
    p.write_bytes(raw)
    with open_image(p) as img:
        scheme, parts = detect(img)
        assert scheme == "mbr" and len(parts) == 2
        assert parts[0].start_offset == 2048 * 512
        assert parts[0].bootable and parts[0].type_label == "NTFS/exFAT"
        assert img.read(parts[0].start_offset, 5) == b"PART1"


def test_gpt_partitions(tmp_path):
    raw = make_gpt_disk()
    p = tmp_path / "d.raw"
    p.write_bytes(raw)
    with open_image(p) as img:
        scheme, parts = detect(img)
        assert scheme == "gpt" and len(parts) == 2
        assert parts[1].name == "ESP"
        assert parts[1].type_label == "EFI System"
        assert parts[0].start_offset == 40 * 512


def test_vhdx_detected_not_supported(tmp_path):
    p = tmp_path / "d.vhdx"
    p.write_bytes(b"vhdxfile" + b"\x00" * 2040)
    assert sniff(p) == "vhdx"
    with pytest.raises(Exception):
        open_image(p)
