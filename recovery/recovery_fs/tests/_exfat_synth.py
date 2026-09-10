"""Hand-build a tiny valid exFAT volume image (one file + one subdir)."""

from __future__ import annotations

import struct

BPS = 512
SPC = 1
CS = BPS * SPC
FAT_SECT = 128
FAT_LEN = 16
HEAP_SECT = 256
CLUSTER_COUNT = 64
ROOT_CL = 2
BITMAP_CL = 3
UPCASE_CL = 4
FILE_CL = 6
SUBDIR_CL = 7
SUBFILE_CL = 8
TOTAL_SECT = HEAP_SECT + CLUSTER_COUNT * SPC + 8


def _ts(y=2026, mo=3, d=16, hh=10, mm=15, ss=20):
    return ((y - 1980) << 25) | (mo << 21) | (d << 16) | (hh << 11) \
        | (mm << 5) | (ss // 2)


def _file_set(name: str, first_cl: int, size: int, is_dir=False):
    fe = bytearray(32)
    fe[0] = 0x85
    fe[1] = 2                                   # secondary count
    struct.pack_into("<H", fe, 4, 0x10 if is_dir else 0x20)
    t = _ts()
    struct.pack_into("<III", fe, 8, t, t, t)

    se = bytearray(32)
    se[0] = 0xC0
    se[1] = 0x03                                # AllocPossible | NoFatChain
    se[3] = len(name)
    struct.pack_into("<Q", se, 8, size)
    struct.pack_into("<I", se, 20, first_cl)
    struct.pack_into("<Q", se, 24, size)

    ne = bytearray(32)
    ne[0] = 0xC1
    nm = name.encode("utf-16-le")[:30]
    ne[2:2 + len(nm)] = nm
    return bytes(fe) + bytes(se) + bytes(ne)


def build_exfat() -> bytes:
    img = bytearray(TOTAL_SECT * BPS)

    bs = img
    bs[0:3] = b"\xeb\x76\x90"
    bs[3:11] = b"EXFAT   "
    struct.pack_into("<Q", bs, 0x40, 0)
    struct.pack_into("<Q", bs, 0x48, TOTAL_SECT)
    struct.pack_into("<I", bs, 0x50, FAT_SECT)
    struct.pack_into("<I", bs, 0x54, FAT_LEN)
    struct.pack_into("<I", bs, 0x58, HEAP_SECT)
    struct.pack_into("<I", bs, 0x5C, CLUSTER_COUNT)
    struct.pack_into("<I", bs, 0x60, ROOT_CL)
    bs[0x6C] = 9                                # bytes/sector shift
    bs[0x6D] = 0                                # sectors/cluster shift
    struct.pack_into("<H", bs, 510, 0xAA55)

    fat = bytearray(FAT_LEN * BPS)
    struct.pack_into("<I", fat, 0, 0xFFFFFFF8)
    struct.pack_into("<I", fat, 4, 0xFFFFFFFF)
    img[FAT_SECT * BPS: FAT_SECT * BPS + len(fat)] = fat

    def cl_off(cl):
        return (HEAP_SECT + (cl - 2) * SPC) * BPS

    hello = b"hello from an exFAT volume - via NoFatChain\n"
    note = b"exfat nested note\n"

    root = bytearray(CS)
    # allocation bitmap
    bm = bytearray(32)
    bm[0] = 0x81
    struct.pack_into("<I", bm, 20, BITMAP_CL)
    struct.pack_into("<Q", bm, 24, (CLUSTER_COUNT + 7) // 8)
    # upcase table (fake but structurally present)
    uc = bytearray(32)
    uc[0] = 0x82
    struct.pack_into("<I", uc, 20, UPCASE_CL)
    struct.pack_into("<Q", uc, 24, 128)
    # volume label
    vl = bytearray(32)
    vl[0] = 0x83
    lbl = "TESTVOL".encode("utf-16-le")
    vl[1] = 7
    vl[2:2 + len(lbl)] = lbl

    root[0:32] = bm
    root[32:64] = uc
    root[64:96] = vl
    p = 96
    fs1 = _file_set("hello.txt", FILE_CL, len(hello))
    root[p:p + len(fs1)] = fs1
    p += len(fs1)
    fs2 = _file_set("sub", SUBDIR_CL, CS, is_dir=True)
    root[p:p + len(fs2)] = fs2
    img[cl_off(ROOT_CL): cl_off(ROOT_CL) + CS] = root

    sub = bytearray(CS)
    sub[0:96] = _file_set("note.txt", SUBFILE_CL, len(note))
    img[cl_off(SUBDIR_CL): cl_off(SUBDIR_CL) + CS] = sub

    img[cl_off(FILE_CL): cl_off(FILE_CL) + len(hello)] = hello
    img[cl_off(SUBFILE_CL): cl_off(SUBFILE_CL) + len(note)] = note
    return bytes(img)
