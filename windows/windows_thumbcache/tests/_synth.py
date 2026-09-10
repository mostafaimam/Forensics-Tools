"""Synthetic thumbcache_256.db + thumbcache_idx.db for the test-suite."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

SIG = b"CMMM"
VERSION = 0x1C           # Windows 8.1
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 60 + b"\xff\xd9"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
BOGUS = b"not an image at all" + b"\x00" * 20


def ft(dt):
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def _entry(cache_id: int, identifier: str, blob: bytes, w=256, h=171) -> bytes:
    ident = identifier.encode("utf-16-le")
    pad = (8 - len(ident) % 8) % 8
    body = bytearray()
    body += struct.pack("<Q", cache_id)                  # +8  entry hash
    body += b"jpg\x00"                                   # +16 extension
    body += struct.pack("<III", len(ident), pad, len(blob))  # +20 sizes
    body += struct.pack("<HH", w, h)                     # +32 dims
    body += struct.pack("<I", 0)                         # +36 unknown
    body += struct.pack("<Q", 0)                         # +40 data checksum
    body += struct.pack("<Q", 0)                         # +48 header checksum
    body += ident + b"\x00" * pad                        # +56 identifier
    body += blob
    entry_size = 8 + len(body)
    out = SIG + struct.pack("<I", entry_size) + bytes(body)
    if len(out) % 8:
        out += b"\x00" * (8 - len(out) % 8)
    return out


ENTRIES = [
    (0x1111111111111111, "1111111111111111", JPEG),
    (0x2222222222222222,
     "C:\\Users\\victim\\AppData\\Local\\Temp\\stolen.jpg", JPEG),
    (0x3333333333333333, "D:\\photos\\holiday\\IMG_2043.png", PNG),
    (0x4444444444444444, "4444444444444444", BOGUS),
]


def build_cache() -> bytes:
    # sig(4) version(4) type(4) first_entry(4) first_avail(4) n_entries(4)
    hdr = SIG + struct.pack("<IIIII", VERSION, 5, 24, 0, len(ENTRIES))
    body = b"".join(_entry(cid, ident, blob) for cid, ident, blob in ENTRIES)
    return hdr + body


def build_index() -> bytes:
    # 24-byte header, then 32-byte entries: cid(8) ft(8) flags(4) offs(3*4)
    hdr = SIG + struct.pack("<IIIII", VERSION, len(ENTRIES), 0, 0, 0)
    out = bytearray(hdr)
    base = datetime(2026, 3, 8, 12, 0, tzinfo=timezone.utc)
    for i, (cid, _ident, _blob) in enumerate(ENTRIES):
        out += struct.pack("<Q", cid)
        out += struct.pack("<Q", ft(base.replace(minute=i * 5)))
        out += struct.pack("<I", 0x1)
        out += struct.pack("<3I", 0xFFFFFFFF, 0x40, 0xFFFFFFFF)
    return bytes(out)
