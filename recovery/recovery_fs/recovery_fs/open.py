"""Open a volume: detect the FS, optionally find the first partition."""

from __future__ import annotations

import struct
from pathlib import Path

from recovery_fs.detect import detect

_UNSUPPORTED = {"ext": "ext2/3/4", "hfsplus": "HFS+", "apfs": "APFS"}


class FsError(Exception):
    pass


def _first_partition_offset(stream) -> int:
    """Very small MBR / GPT probe -> the byte offset of the first FS slice."""
    stream.seek(0)
    mbr = stream.read(512)
    if mbr[510:512] != b"\x55\xaa":
        return 0
    # GPT?
    stream.seek(512)
    if stream.read(8) == b"EFI PART":
        stream.seek(512)
        hdr = stream.read(92)
        lba = struct.unpack_from("<Q", hdr, 72)[0]
        num = struct.unpack_from("<I", hdr, 80)[0]
        esz = struct.unpack_from("<I", hdr, 84)[0]
        stream.seek(lba * 512)
        for i in range(min(num, 128)):
            ent = stream.read(esz)
            if ent[:16] == b"\x00" * 16:
                continue
            start = struct.unpack_from("<Q", ent, 32)[0]
            if start:
                return start * 512
        return 0
    # MBR primary partitions
    best = None
    for i in range(4):
        p = mbr[446 + i * 16: 446 + (i + 1) * 16]
        ptype = p[4]
        lba = struct.unpack_from("<I", p, 8)[0]
        if ptype in (0x00, 0x05, 0x0F, 0xEE):
            continue
        if lba:
            best = lba * 512 if best is None else min(best, lba * 512)
    return best or 0


def open_fs(path: str, *, offset: int | None = None, autodetect=True):
    p = Path(path)
    stream = p.open("rb")
    off = offset
    if off is None:
        off = 0
        if autodetect:
            probe = _peek(stream, 0)
            if detect(probe) == "unknown":
                cand = _first_partition_offset(stream)
                if cand and detect(_peek(stream, cand)) != "unknown":
                    off = cand
    fs = detect(_peek(stream, off))
    if fs == "ntfs":
        from recovery_fs.ntfsadapter import NtfsAdapter
        return NtfsAdapter(stream, off), off, "ntfs"
    if fs == "fat":
        from recovery_fs.fatfs import FatBackend
        b = FatBackend(stream, off)
        return b, off, b.type
    if fs == "exfat":
        from recovery_fs.exfatfs import ExfatBackend
        return ExfatBackend(stream, off), off, "exfat"
    if fs in _UNSUPPORTED:
        stream.close()
        raise FsError(f"{_UNSUPPORTED[fs]} detected at offset {off:#x} - "
                      f"not walkable in v0.1 (recovery_carve can still "
                      f"carve it)")
    stream.close()
    raise FsError(f"no supported file system found "
                  f"(detected: {fs}) at offset {off:#x}")


def _peek(stream, off: int) -> bytes:
    stream.seek(off)
    data = stream.read(0x600)
    return data
