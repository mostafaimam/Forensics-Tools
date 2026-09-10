"""Hand-build a tiny valid FAT16 volume image."""

from __future__ import annotations

import struct

BPS = 512
SPC = 1
RSVD = 1
NFATS = 1
ROOT_ENTS = 16
TOTAL_SECT = 8192              # -> > 4085 data clusters => FAT16
FATSZ = 34                     # sectors; covers 8192 x 2-byte entries


def _dt(y=2026, mo=3, d=16, hh=9, mm=30, ss=0):
    date = ((y - 1980) << 9) | (mo << 5) | d
    time = (hh << 11) | (mm << 5) | (ss // 2)
    return date, time


def _dirent(name8, ext3, attr, first_cl, size, *, deleted=False):
    e = bytearray(32)
    nm = name8.encode().ljust(8)[:8]
    ex = ext3.encode().ljust(3)[:3]
    e[0:8] = nm
    e[8:11] = ex
    if deleted:
        e[0] = 0xE5
    e[0x0B] = attr
    cd, ct = _dt()
    struct.pack_into("<HH", e, 0x0E, ct, cd)     # create time/date
    struct.pack_into("<H", e, 0x12, cd)          # access date
    struct.pack_into("<HH", e, 0x16, ct, cd)     # write time/date
    struct.pack_into("<H", e, 0x14, first_cl >> 16)
    struct.pack_into("<H", e, 0x1A, first_cl & 0xFFFF)
    struct.pack_into("<I", e, 0x1C, size)
    return bytes(e)


def build_fat16() -> bytes:
    root_dir_sectors = (ROOT_ENTS * 32 + BPS - 1) // BPS
    first_data = RSVD + NFATS * FATSZ + root_dir_sectors
    img = bytearray(TOTAL_SECT * BPS)

    # -- boot sector --
    bs = img
    bs[0:3] = b"\xeb\x3c\x90"
    bs[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", bs, 0x0B, BPS)
    bs[0x0D] = SPC
    struct.pack_into("<H", bs, 0x0E, RSVD)
    bs[0x10] = NFATS
    struct.pack_into("<H", bs, 0x11, ROOT_ENTS)
    struct.pack_into("<H", bs, 0x13, TOTAL_SECT)
    bs[0x15] = 0xF8
    struct.pack_into("<H", bs, 0x16, FATSZ)
    bs[0x36:0x3E] = b"FAT16   "
    struct.pack_into("<H", bs, 510, 0xAA55)

    # -- files: HELLO.TXT c2, DOCS/ c4, DOCS/NOTE.TXT c5, deleted SECRET c3 --
    hello = b"hello from a FAT16 volume\n"
    note = b"nested note file\n"
    secret = b"deleted but recoverable\n"

    fat = bytearray(FATSZ * BPS)
    struct.pack_into("<H", fat, 0, 0xFFF8)
    struct.pack_into("<H", fat, 2, 0xFFFF)
    struct.pack_into("<H", fat, 2 * 2, 0xFFFF)     # cl 2 (HELLO) EOC
    struct.pack_into("<H", fat, 3 * 2, 0xFFFF)     # cl 3 (SECRET) EOC
    struct.pack_into("<H", fat, 4 * 2, 0xFFFF)     # cl 4 (DOCS dir) EOC
    struct.pack_into("<H", fat, 5 * 2, 0xFFFF)     # cl 5 (NOTE) EOC
    img[RSVD * BPS: RSVD * BPS + len(fat)] = fat

    # root directory
    root = bytearray(root_dir_sectors * BPS)
    ents = [
        _dirent("HELLO", "TXT", 0x20, 2, len(hello)),
        _dirent("SECRET", "TXT", 0x20, 3, len(secret), deleted=True),
        _dirent("DOCS", "", 0x10, 4, 0),
    ]
    root[:32 * len(ents)] = b"".join(ents)
    root_off = (RSVD + NFATS * FATSZ) * BPS
    img[root_off: root_off + len(root)] = root

    def cluster_off(cl):
        return (first_data + (cl - 2) * SPC) * BPS

    img[cluster_off(2): cluster_off(2) + len(hello)] = hello
    img[cluster_off(3): cluster_off(3) + len(secret)] = secret
    # DOCS dir contents at cluster 4
    docs = bytearray(BPS)
    docs[0:32] = _dirent(".", "", 0x10, 4, 0)
    docs[32:64] = _dirent("..", "", 0x10, 0, 0)
    docs[64:96] = _dirent("NOTE", "TXT", 0x20, 5, len(note))
    img[cluster_off(4): cluster_off(4) + BPS] = docs
    img[cluster_off(5): cluster_off(5) + len(note)] = note

    return bytes(img)
