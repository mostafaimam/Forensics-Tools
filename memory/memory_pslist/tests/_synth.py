"""Synthetic Windows _EPROCESS-shaped blobs inside a LiME dump."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_LIME = struct.Struct("<IIQQQ")


def _ft(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc) - _FT_EPOCH)
               .total_seconds() * 10_000_000)


def eprocess(name: str, pid: int, ppid: int, create: datetime,
             exit_dt: datetime | None = None, *, protected=False) -> bytes:
    tag = b"Pro\xe3" if protected else b"Proc"
    b = bytearray(0x400)
    # pool header (16 bytes): tag at +4
    b[4:8] = tag
    body = 16
    struct.pack_into("<Q", b, body + 0x00, _ft(create))
    struct.pack_into("<Q", b, body + 0x08, _ft(exit_dt) if exit_dt else 0)
    struct.pack_into("<Q", b, body + 0x28, pid)          # closest to name
    struct.pack_into("<Q", b, body + 0x20, ppid)
    nm = name.encode("latin-1")[:15]
    b[body + 0x30: body + 0x30 + len(nm)] = nm
    b[body + 0x30 + len(nm)] = 0
    return bytes(b)


def lime_with(blobs: list[bytes], gap: int = 0x2000) -> bytes:
    ram = bytearray()
    for blob in blobs:
        ram += blob + b"\x00" * gap
    size = (len(ram) + 0xFFF) & ~0xFFF
    ram += b"\x00" * (size - len(ram))
    return _LIME.pack(0x4C694D45, 1, 0, size - 1, 0) + bytes(ram)
