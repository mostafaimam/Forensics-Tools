"""LiME (Linux Memory Extractor) format - header per physical range."""

from __future__ import annotations

import struct
from dataclasses import dataclass

_MAGIC = 0x4C694D45          # "LiME"
_VERSION = 1
_HDR = struct.Struct("<IIQQQ")          # magic, version, s_addr, e_addr, reserved
HEADER_SIZE = _HDR.size                 # 32


def header(start: int, end_inclusive: int) -> bytes:
    """A LiME range header.  *end_inclusive* is the last byte's address."""
    return _HDR.pack(_MAGIC, _VERSION, start, end_inclusive, 0)


@dataclass
class LimeRange:
    start: int
    end: int            # exclusive
    data_offset: int    # offset of this range's bytes within the .lime file

    @property
    def size(self) -> int:
        return self.end - self.start


def parse_headers(fh) -> list[LimeRange]:
    """Walk a .lime file's range headers (seeks past each range's data)."""
    out: list[LimeRange] = []
    fh.seek(0)
    while True:
        raw = fh.read(HEADER_SIZE)
        if len(raw) < HEADER_SIZE:
            break
        magic, version, s, e, _res = _HDR.unpack(raw)
        if magic != _MAGIC or version != _VERSION:
            raise ValueError(f"bad LiME header at range {len(out)}")
        size = e - s + 1
        out.append(LimeRange(s, s + size, fh.tell()))
        fh.seek(size, 1)
    return out
