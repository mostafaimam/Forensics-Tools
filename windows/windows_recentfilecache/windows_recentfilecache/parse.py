"""Parse RecentFileCache.bcf."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_SIGS = (b"\xfe\xff\xee\xff", b"\xfe\xff\xfe\xff", b"\x11\x22\x33\x44")
HEADER_SIZE = 0x14


@dataclass
class Entry:
    path: str
    name: str
    index: int
    offset: int

    def row(self) -> dict:
        return {"index": self.index, "name": self.name, "path": self.path,
                "offset": self.offset}


@dataclass
class Parsed:
    entries: list = field(default_factory=list)
    signature: str = ""
    header_ok: bool = False
    trailing_bytes: int = 0
    parse_error: str = ""


def parse(data: bytes) -> Parsed:
    p = Parsed()
    if len(data) < HEADER_SIZE:
        p.parse_error = "shorter than the 20-byte header"
        return p
    p.signature = data[:4].hex()
    p.header_ok = data[:4] in _SIGS

    pos = HEADER_SIZE
    idx = 0
    n = len(data)
    while pos + 4 <= n:
        (nchars,) = struct.unpack_from("<I", data, pos)
        if nchars == 0 or nchars > 32767:
            p.trailing_bytes = n - pos
            break
        start = pos + 4
        strbytes = (nchars + 1) * 2          # includes the end-of-string char
        if start + strbytes > n:
            p.trailing_bytes = n - pos
            break
        raw = data[start:start + nchars * 2]
        try:
            path = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            path = raw.decode("utf-16-le", "replace")
        path = path.rstrip("\x00")
        name = path.rsplit("\\", 1)[-1]
        p.entries.append(Entry(path=path, name=name, index=idx, offset=pos))
        idx += 1
        pos = start + strbytes
    else:
        p.trailing_bytes = n - pos
    return p
