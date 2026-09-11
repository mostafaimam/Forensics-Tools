"""Embed synthetic `regf` hive headers into a flat memory image."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def build_header(name: str, *, seq1=5, seq2=5,
                 when=datetime(2026, 3, 16, 9, 0, tzinfo=timezone.utc)):
    h = bytearray(0x1000)
    h[0:4] = b"regf"
    struct.pack_into("<II", h, 4, seq1, seq2)
    struct.pack_into("<Q", h, 0x0C, ft(when))
    struct.pack_into("<II", h, 0x14, 1, 5)          # major.minor
    struct.pack_into("<II", h, 0x1C, 0, 1)          # file type/format
    struct.pack_into("<II", h, 0x24, 0x20, 0x3000)  # root cell, length
    nm = name.encode("utf-16-le") + b"\x00\x00"
    h[0x30:0x30 + len(nm)] = nm
    return bytes(h)


def build_image() -> bytes:
    pad = b"\x00" * 0x400
    img = bytearray()
    img += pad
    img += build_header("\\Device\\HarddiskVolume2\\Users\\victim\\NTUSER.DAT")
    img += pad
    img += build_header("\\Device\\HarddiskVolume2\\Windows\\System32\\"
                        "config\\SYSTEM", seq1=9, seq2=8)   # dirty
    img += pad
    return bytes(img)
