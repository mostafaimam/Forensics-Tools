"""Identify the file system at a given offset in an image / device."""

from __future__ import annotations

import struct


def detect(head: bytes) -> str:
    """head must be at least the first 0x600 bytes of the volume."""
    if len(head) < 0x200:
        return "unknown"
    oem = head[3:11]
    if head[3:11] == b"NTFS    ":
        return "ntfs"
    if head[3:11] == b"EXFAT   ":
        return "exfat"
    # ext2/3/4: magic 0xEF53 at offset 0x438 (superblock at 0x400 + 0x38)
    if len(head) >= 0x440 and head[0x438:0x43A] == b"\x53\xef":
        return "ext"
    # HFS+ / HFSX: signature at 0x400
    if len(head) >= 0x402 and head[0x400:0x402] in (b"H+", b"HX"):
        return "hfsplus"
    # APFS container superblock: 'NXSB' magic at 0x20
    if len(head) >= 0x24 and head[0x20:0x24] == b"NXSB":
        return "apfs"
    # FAT: BPB looks sane and FS type label present, or heuristics
    try:
        bps = struct.unpack_from("<H", head, 0x0B)[0]
        spc = head[0x0D]
        rsvd = struct.unpack_from("<H", head, 0x0E)[0]
        nfats = head[0x10]
        if bps in (512, 1024, 2048, 4096) and spc in (
                1, 2, 4, 8, 16, 32, 64, 128) and 1 <= nfats <= 2 and rsvd >= 1:
            if head[0x52:0x5A].rstrip() in (b"FAT32",):
                return "fat"
            if head[0x36:0x3E].rstrip() in (b"FAT12", b"FAT16", b"FAT"):
                return "fat"
            if oem[:3] in (b"MSD", b"mkf", b"FRD") or oem.rstrip():
                return "fat"
    except (struct.error, IndexError):
        pass
    return "unknown"
