"""Build synthetic disk images with recognisable filesystem signatures."""

from __future__ import annotations

import struct
import uuid

SECTOR = 512


def _ntfs_bs() -> bytes:
    b = bytearray(512)
    b[0:3] = b"\xEB\x52\x90"
    b[3:11] = b"NTFS    "
    b[0x1FE:0x200] = b"\x55\xAA"
    return bytes(b)


def _fat32_bs() -> bytes:
    b = bytearray(512)
    b[0:3] = b"\xEB\x58\x90"
    b[3:11] = b"MSDOS5.0"
    b[0x52:0x5A] = b"FAT32   "
    b[0x1FE:0x200] = b"\x55\xAA"
    return bytes(b)


def _ext4_sb() -> bytes:
    # a 2 KiB region: superblock at +0x400, magic 0xEF53 at +0x438,
    # feature_incompat (0x400+0x60) with a 64bit bit set -> "ext4"
    b = bytearray(0x800)
    struct.pack_into("<H", b, 0x438, 0xEF53)
    struct.pack_into("<I", b, 0x400 + 0x5C, 0x0004)     # has_journal
    struct.pack_into("<I", b, 0x400 + 0x60, 0x0200)     # 64bit
    return bytes(b)


def _swap_hdr() -> bytes:
    b = bytearray(4096)
    b[4086:4096] = b"SWAPSPACE2"
    return bytes(b)


def _luks_hdr() -> bytes:
    b = bytearray(4096)
    b[0:6] = b"LUKS\xba\xbe"
    struct.pack_into(">H", b, 6, 2)
    return bytes(b)


def make_mbr_disk(size=16 * 1024 * 1024) -> bytes:
    disk = bytearray(size)
    # (start_lba, count_sectors, type, payload)
    layout = [
        (2048, 8192, 0x07, _ntfs_bs()),
        (10240, 8192, 0x83, _ext4_sb()),
        (20480, 4096, 0x0C, _fat32_bs()),
        (24576, 4096, 0x82, _swap_hdr()),
    ]
    mbr = bytearray(512)
    for i, (start, count, ptype, payload) in enumerate(layout):
        off = 446 + i * 16
        mbr[off] = 0x80 if i == 0 else 0x00
        mbr[off + 4] = ptype
        struct.pack_into("<II", mbr, off + 8, start, count)
        disk[start * SECTOR:start * SECTOR + len(payload)] = payload
    mbr[510:512] = b"\x55\xAA"
    disk[0:512] = mbr
    return bytes(disk)


def make_gpt_disk(size=16 * 1024 * 1024) -> bytes:
    disk = bytearray(size)
    total = size // SECTOR
    disk[446 + 4] = 0xEE
    struct.pack_into("<II", disk, 446 + 8, 1, total - 1)
    disk[510:512] = b"\x55\xAA"

    parts = [
        ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", 40, 2087, "EFI System",
         _fat32_bs()),
        ("0fc63daf-8483-4772-8e79-3d69d8477de4", 2088, 10279, "linux",
         _ext4_sb()),
        ("e6d6d379-f507-44c2-a23c-238f2a3df928", 10280, 14375, "lvm",
         b"\x00" * 512 + b"LABELONE"),
        ("cafeb0ba-0000-0000-0000-000000000000", 14376, 18471, "encrypted",
         _luks_hdr()),
    ]
    entries = bytearray(128 * 128)
    for i, (tguid, first, last, name, payload) in enumerate(parts):
        e = bytearray(128)
        e[0:16] = uuid.UUID(tguid).bytes_le
        e[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQ", e, 32, first, last)
        nm = name.encode("utf-16-le")
        e[56:56 + len(nm)] = nm
        entries[i * 128:(i + 1) * 128] = e
        disk[first * SECTOR:first * SECTOR + len(payload)] = payload

    hdr = bytearray(512)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<III", hdr, 8, 0x00010000, 92, 0)
    struct.pack_into("<QQ", hdr, 24, 1, total - 1)          # current, backup
    struct.pack_into("<QQ", hdr, 40, 34, total - 34)        # first, last usable
    hdr[56:72] = uuid.uuid4().bytes_le
    struct.pack_into("<Q", hdr, 72, 2)                       # entries LBA
    struct.pack_into("<II", hdr, 80, len(parts), 128)
    disk[SECTOR:SECTOR + 512] = hdr
    disk[2 * SECTOR:2 * SECTOR + len(entries)] = entries
    return bytes(disk)
