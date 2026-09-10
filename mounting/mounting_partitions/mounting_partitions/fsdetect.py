"""Identify the filesystem / container in the first sectors of a slice."""

from __future__ import annotations

import struct


def detect(head: bytes) -> str:
    """head: at least the first 65536 bytes of a partition / disk."""
    if len(head) < 512:
        return ""

    # --- boot-sector / offset-3 OEM based ---
    oem = head[3:11]
    if head[0x1FE:0x200] == b"\x55\xAA":
        if oem[:5] == b"NTFS ":
            return "NTFS"
        if oem[:5] == b"EXFAT":
            return "exFAT"
        if head[0x36:0x3B] == b"FAT12":
            return "FAT12"
        if head[0x36:0x3B] == b"FAT16":
            return "FAT16"
        if head[0x52:0x57] == b"FAT32":
            return "FAT32"
        if oem == b"-FVE-FS-" or head[0x03:0x0B] == b"-FVE-FS-":
            return "BitLocker"
        if oem == b"MSWIN4.1" or oem[:3] == b"MSD":
            return "FAT"

    # BitLocker also has a GUID at 0x160 for the newer layout
    if head[0:8] == b"\xEB\x58\x90-FVE" or b"-FVE-FS-" in head[:16]:
        return "BitLocker"

    # --- ext2/3/4: magic 0xEF53 at superblock offset 0x38 (block+0x400) ---
    if len(head) >= 0x440 and head[0x438:0x43A] == b"\x53\xEF":
        feat_incompat = struct.unpack_from("<I", head, 0x400 + 0x60)[0] \
            if len(head) >= 0x464 else 0
        has_journal = struct.unpack_from("<I", head, 0x400 + 0x5C)[0] & 0x4 \
            if len(head) >= 0x460 else 0
        if feat_incompat & 0x200:              # 64-bit / extents-ish
            return "ext4"
        return "ext4" if has_journal else "ext2/3"

    # --- XFS ---
    if head[:4] == b"XFSB":
        return "XFS"
    # --- Btrfs: magic "_BHRfS_M" at 0x10040 ---
    if len(head) >= 0x10048 and head[0x10040:0x10048] == b"_BHRfS_M":
        return "Btrfs"
    # --- ReiserFS ---
    if len(head) >= 0x10000 + 9 and head[0x10034:0x1003D] in (
            b"ReIsErFs\x00", b"ReIsEr2Fs", b"ReIsEr3Fs"):
        return "ReiserFS"
    # --- F2FS ---
    if len(head) >= 0x1404 and head[0x400:0x404] == b"\x10\x20\xF5\xF2":
        return "F2FS"

    # --- APFS container: "NXSB" at 0x20 ---
    if len(head) >= 0x24 and head[0x20:0x24] == b"NXSB":
        return "APFS container"
    # --- HFS+ / HFSX: at 0x400 ---
    if len(head) >= 0x402 and head[0x400:0x402] in (b"H+", b"HX"):
        return "HFS+"
    if len(head) >= 0x402 and head[0x400:0x402] == b"BD":
        return "HFS"

    # --- LVM2: "LABELONE" in sector 1 (offset 512) ---
    if len(head) >= 512 + 8 and head[512:520] == b"LABELONE":
        return "LVM2 (PV)"
    if len(head) >= 8 and head[:8] == b"LABELONE":
        return "LVM2 (PV)"

    # --- LUKS ---
    if head[:6] == b"LUKS\xba\xbe":
        ver = struct.unpack_from(">H", head, 6)[0]
        return f"LUKS{ver or 1}"

    # --- Linux swap: signature at the end of the first page ---
    if len(head) >= 4096 and head[4086:4096] in (b"SWAPSPACE2", b"SWAP-SPACE"):
        return "Linux swap"

    # --- MD RAID (0.90 superblock magic) ---
    if head[:4] == b"\xfc\x4e\x2b\xa9":
        return "Linux MD RAID"

    # --- ISO9660 ---
    if len(head) >= 0x8006 and head[0x8001:0x8006] == b"CD001":
        return "ISO9660"

    return ""
