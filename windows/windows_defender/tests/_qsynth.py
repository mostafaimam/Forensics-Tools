"""Build a synthetic Defender Quarantine\\Entries record."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

from windows_defender.quarantine import rc4

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(dt):
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def build_entry(*, threat="Trojan:Win32/Wacatac.B!ml",
                path="C:\\Users\\victim\\Downloads\\invoice.exe",
                when=datetime(2026, 3, 16, 10, 15, 0, tzinfo=timezone.utc),
                threat_id=2147735503) -> bytes:
    gid = uuid.UUID("11111111-2222-3333-4444-555555555555")
    sid = uuid.UUID("99999999-8888-7777-6666-555555555555")

    sec1 = bytearray(0x30)
    sec1[0:16] = gid.bytes_le
    sec1[16:32] = sid.bytes_le
    struct.pack_into("<Q", sec1, 0x20, _ft(when))
    struct.pack_into("<Q", sec1, 0x28, threat_id)
    sec1 += threat.encode("utf-8") + b"\x00"

    # section 2: one resource
    res = bytearray()
    res += path.encode("utf-16-le") + b"\x00\x00"
    fields = bytearray()
    # field: type 0x06 (kind) = "file"
    kind = "file".encode("utf-16-le")
    fields += struct.pack("<HH", len(kind), 0x06) + kind
    while len(fields) % 4:
        fields += b"\x00"
    # field: type 0x04 (filetime)
    fields += struct.pack("<HH", 8, 0x04) + struct.pack("<Q", _ft(when))
    # field: sha1 (size 20)
    fields += struct.pack("<HH", 20, 0x00) + bytes(range(20))
    res += struct.pack("<I", 3) + fields

    sec2 = bytearray()
    sec2 += struct.pack("<I", 1)          # count
    sec2 += struct.pack("<I", 8)          # offset to resource 0
    sec2 += bytes(res)

    header = bytearray(0x3C)
    struct.pack_into("<I", header, 0x28, len(sec1))
    struct.pack_into("<I", header, 0x2C, len(sec2))

    return rc4(bytes(header)) + rc4(bytes(sec1)) + rc4(bytes(sec2))


def write_quarantine(root, **kw):
    ent = root / "Entries"
    ent.mkdir(parents=True, exist_ok=True)
    (ent / "{11111111-2222-3333-4444-555555555555}").write_bytes(
        build_entry(**kw))
    return root
