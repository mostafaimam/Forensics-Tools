import io
import struct

import pytest

from _synth import build_ntfs_image
from recovery_metadata.ntfs.boot import NotNtfsError, parse_boot_sector
from recovery_metadata.ntfs.record import RecordError, apply_fixup, parse_record
from recovery_metadata.ntfs.runlist import Run, decode_runlist
from recovery_metadata.ntfs.volume import NtfsVolume


def test_decode_runlist_basic():
    # 0x21 03 40 06  -> length 3, offset 0x0640 ; then 0x11 05 FF -> +(-1)
    data = bytes.fromhex("21034006") + bytes.fromhex("1105ff") + b"\x00"
    runs = decode_runlist(data)
    assert runs[0] == Run(0x0640, 3)
    assert runs[1] == Run(0x0640 - 1, 5)


def test_decode_runlist_sparse():
    data = bytes([0x01, 0x08]) + bytes([0x21, 0x02, 0x10, 0x00]) + b"\x00"
    runs = decode_runlist(data)
    assert runs[0] == Run(None, 8)
    assert runs[1].lcn == 0x10


def test_boot_sector_rejects_non_ntfs():
    with pytest.raises(NotNtfsError):
        parse_boot_sector(b"\x00" * 512)


def test_fixup_detects_corruption():
    img, _ = build_ntfs_image()
    rec = bytearray(img[4 * 4096: 4 * 4096 + 1024])  # $MFT record 0
    # corrupt a sector's last two bytes
    rec[511] ^= 0xFF
    with pytest.raises(RecordError):
        apply_fixup(rec)


def test_parse_mft_self_record():
    img, _ = build_ntfs_image()
    boot = parse_boot_sector(img[:512])
    raw = img[boot.mft_offset: boot.mft_offset + boot.bytes_per_mft_record]
    rec = parse_record(raw, 0)
    assert rec.in_use
    data = [a for a in rec.by_type(0x80) if a.name == ""]
    assert data and data[0].non_resident


def test_volume_list_and_paths():
    img, expected = build_ntfs_image()
    vol = NtfsVolume(io.BytesIO(img))
    entries = {e.name: e for e in vol.iter_entries()}
    assert "hello.txt" in entries
    assert "secret.txt" in entries
    assert entries["hello.txt"].in_use is True
    assert entries["secret.txt"].deleted is True
    assert vol.full_path(entries["hello.txt"]) == "hello.txt"
    assert entries["secret.txt"].size == len(expected["secret.txt"])


def test_volume_extract_resident_and_deleted_nonresident():
    img, expected = build_ntfs_image()
    vol = NtfsVolume(io.BytesIO(img))
    entries = {e.name: e for e in vol.iter_entries()}
    assert vol.read_file(entries["hello.txt"]) == expected["hello.txt"]
    assert vol.read_file(entries["secret.txt"]) == expected["secret.txt"]


def test_standard_information_times():
    img, _ = build_ntfs_image()
    vol = NtfsVolume(io.BytesIO(img))
    e = next(x for x in vol.iter_entries() if x.name == "hello.txt")
    assert e.si is not None and e.si.modified is not None
    assert e.si.modified.year == 2024
