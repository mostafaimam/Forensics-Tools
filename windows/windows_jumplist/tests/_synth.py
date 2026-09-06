"""Build a minimal OLE2 compound file + DestList for the test-suite.

All streams are kept >= the 4096-byte mini-stream cutoff so only the regular
FAT is exercised (no mini-FAT), which keeps the writer small.
"""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

SECTOR = 512
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc) - _FT_EPOCH).total_seconds() * 1e7)


def _dir_entry(name: str, etype: int, start: int, size: int) -> bytes:
    b = bytearray(128)
    nm = name.encode("utf-16-le") + b"\x00\x00"
    b[:len(nm)] = nm
    struct.pack_into("<H", b, 64, len(nm))
    b[66] = etype
    b[67] = 1                                      # colour
    struct.pack_into("<III", b, 68, NOSTREAM, NOSTREAM, NOSTREAM)
    struct.pack_into("<I", b, 116, start)
    struct.pack_into("<Q", b, 120, size)
    return bytes(b)


def build_ole(streams: dict[str, bytes]) -> bytes:
    # sector 0 = FAT, sector 1 = directory, then stream data.
    # Keep every stream >= the 4096 cutoff so the reader uses the regular FAT.
    streams = {k: (v if len(v) >= 4096 else v + b"\x00" * (4096 - len(v)))
               for k, v in streams.items()}

    def nsec(data: bytes) -> int:
        return (len(data) + SECTOR - 1) // SECTOR

    layout = []
    cur = 2
    for name, data in streams.items():
        count = max(nsec(data), 1)
        layout.append((name, cur, len(data), count))
        cur += count
    total_sectors = cur

    fat = [FREESECT] * max(total_sectors, 128)
    fat[0] = FATSECT
    fat[1] = ENDOFCHAIN
    for _name, start, _size, count in layout:
        for i in range(count):
            fat[start + i] = (start + i + 1) if i < count - 1 else ENDOFCHAIN

    header = bytearray(SECTOR)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HH", header, 0x1A, 0x003E, 0x0003)     # minor, major
    struct.pack_into("<H", header, 0x1E, 9)                   # sector shift
    struct.pack_into("<H", header, 0x20, 6)                   # mini shift
    struct.pack_into("<I", header, 0x2C, 1)                   # num FAT sectors
    struct.pack_into("<I", header, 0x30, 1)                   # first dir sector
    struct.pack_into("<I", header, 0x38, 4096)               # mini cutoff
    struct.pack_into("<I", header, 0x3C, ENDOFCHAIN)          # first mini-FAT
    struct.pack_into("<I", header, 0x40, 0)
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)          # first DIFAT
    struct.pack_into("<I", header, 0x48, 0)
    struct.pack_into("<I", header, 0x4C, 0)                   # DIFAT[0] = FAT sec 0
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + i * 4, FREESECT)

    fat_sector = b"".join(struct.pack("<I", v) for v in fat[:SECTOR // 4])

    directory = bytearray()
    directory += _dir_entry("Root Entry", 5, ENDOFCHAIN, 0)
    for name, start, size, _count in layout:
        directory += _dir_entry(name, 2, start, size)
    while len(directory) % SECTOR:
        directory += _dir_entry("", 0, 0, 0)

    body = bytearray()
    for _name, _start, _size, count in layout:
        data = streams[_name]
        body += data + b"\x00" * (count * SECTOR - len(data))

    return bytes(header) + fat_sector + bytes(directory) + bytes(body)


# ---- DestList ----------------------------------------------------------
def destlist_v4(entries: list[tuple[int, str, datetime, bool]]) -> bytes:
    out = bytearray(struct.pack("<III", 4, len(entries), 0))   # ver, count, pinned
    out += struct.pack("<I", 0)                    # unknown float
    out += struct.pack("<I", entries[0][0] if entries else 0)   # last entry #
    out += b"\x00" * 12                             # -> 32-byte header
    for num, path, when, pinned in entries:
        e = bytearray(0x80)
        e[0:8] = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        e[0x48:0x48 + 11] = b"WORKSTATION"
        struct.pack_into("<I", e, 0x58, num)
        struct.pack_into("<f", e, 0x60, 1.0)
        struct.pack_into("<Q", e, 0x64, ft(when))
        struct.pack_into("<i", e, 0x6C, 0 if pinned else -1)
        struct.pack_into("<I", e, 0x74, 3)         # access count
        p = path.encode("utf-16-le")
        out += bytes(e) + struct.pack("<H", len(path)) + p + b"\x00\x00\x00\x00"
    return bytes(out)


def sample_lnk(target: str) -> bytes:
    from _lnk_synth import build_lnk
    return build_lnk(target=target)


def build_jumplist(app_id: str = "12dc1ea8e34b5a6") -> tuple[bytes, str]:
    from _lnk_synth import build_lnk
    t0 = datetime(2024, 5, 1, 10, 0, tzinfo=timezone.utc)
    from datetime import timedelta
    entries = [
        (3, r"C:\Users\a\Desktop\latest.png", t0 + timedelta(hours=5), False),
        (1, r"E:\work\old.jpg", t0, True),
    ]
    streams = {
        "DestList": destlist_v4(entries),
        "3": build_lnk(target=r"C:\Users\a\Desktop\latest.png", serial=0xAABBCCDD),
        "1": build_lnk(target=r"E:\work\old.jpg", serial=0x11223344),
    }
    name = f"{app_id}.automaticDestinations-ms"
    return build_ole(streams), name
