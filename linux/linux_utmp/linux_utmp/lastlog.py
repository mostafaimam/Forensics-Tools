"""Parse ``/var/log/lastlog`` - a flat array indexed by UID.

Each entry is 292 bytes on Linux::

    0x000  int32     ll_time   (Unix seconds)
    0x004  char[32]  ll_line
    0x024  char[256] ll_host
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

ENTRY_SIZE = 292


@dataclass
class LastlogEntry:
    uid: int
    timestamp: datetime | None
    line: str
    host: str


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def parse(data: bytes, big_endian: bool = False):
    o = ">" if big_endian else "<"
    n = len(data) - (len(data) % ENTRY_SIZE)
    for uid in range(n // ENTRY_SIZE):
        base = uid * ENTRY_SIZE
        ll_time = struct.unpack_from(f"{o}I", data, base)[0]
        line = _cstr(data[base + 4:base + 36])
        host = _cstr(data[base + 36:base + 292])
        if ll_time == 0 and not line and not host:
            continue                      # UID never logged in
        ts = None
        if ll_time:
            try:
                ts = datetime.fromtimestamp(ll_time, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                ts = None
        yield LastlogEntry(uid, ts, line, host)


def looks_like_lastlog(data: bytes) -> bool:
    return len(data) >= ENTRY_SIZE and len(data) % ENTRY_SIZE == 0 \
        and len(data) % 384 != 0
