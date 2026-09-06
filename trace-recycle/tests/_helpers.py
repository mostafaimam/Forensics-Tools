"""Synthetic Recycle Bin artefact builders for the test suite."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def to_filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def make_i_v2(path: str, size: int, deleted: datetime) -> bytes:
    body = path.encode("utf-16-le") + b"\x00\x00"
    nchars = len(path) + 1
    return struct.pack("<QQQ", 2, size, to_filetime(deleted)) + \
        struct.pack("<I", nchars) + body


def make_i_v1(path: str, size: int, deleted: datetime) -> bytes:
    body = (path.encode("utf-16-le") + b"\x00\x00").ljust(520, b"\x00")[:520]
    return struct.pack("<QQQ", 1, size, to_filetime(deleted)) + body


def make_info2_record(path: str, index: int, drive_num: int, size: int,
                      deleted: datetime, active: bool = True) -> bytes:
    rec = bytearray(0x320)
    ansi = path.encode("latin-1", "replace")[:259].ljust(260, b"\x00")
    rec[0:260] = ansi
    if not active:
        rec[0] = 0
    struct.pack_into("<I", rec, 0x104, index)
    struct.pack_into("<I", rec, 0x108, drive_num)
    struct.pack_into("<Q", rec, 0x10C, to_filetime(deleted))
    struct.pack_into("<I", rec, 0x114, size)
    uni = (path.encode("utf-16-le") + b"\x00\x00").ljust(520, b"\x00")[:520]
    rec[0x118:0x118 + 520] = uni
    return bytes(rec)


def make_info2(records: list[bytes], version: int = 5) -> bytes:
    header = struct.pack("<IIII", version, 0, 0, 0x320)
    return header + b"".join(records)
