r"""Registry hive (``regf``) container: base block, hive bins, cells.

Base block (first 4096 bytes)::

    0x00  4   "regf"
    0x04  u32 primary sequence number
    0x08  u32 secondary sequence number   (== primary when the hive is clean)
    0x0c  u64 last-written time (FILETIME, UTC)
    0x14  u32 major version
    0x18  u32 minor version
    0x1c  u32 file type   (0 = primary)
    0x20  u32 file format (1 = direct memory load)
    0x24  u32 root cell offset  (relative to the start of the first hive bin
                                 == this offset + 4096)
    0x28  u32 hive bins data size
    0x30  48  UTF-16LE embedded file name
    0x1fc u32 XOR-32 checksum of the first 508 bytes

Hive bin header (32 bytes, every 4096 bytes)::

    0x00  4   "hbin"
    0x04  u32 offset of this bin from the first bin
    0x08  u32 bin size (multiple of 4096)

Cell::

    0x00  i32 size   (negative => allocated, positive => free); |size| includes
                     these 4 bytes and is rounded up to a multiple of 8
    0x04  ..  cell data (a keyed structure such as ``nk`` / ``vk`` / ``lf``)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

BASE_BLOCK_SIZE = 4096
HBIN_SIZE = 4096
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class HiveError(ValueError):
    pass


def filetime_to_utc(ticks: int) -> datetime | None:
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class BaseBlock:
    primary_sequence: int
    secondary_sequence: int
    last_written: datetime | None
    major_version: int
    minor_version: int
    root_cell_offset: int
    hive_bins_size: int
    file_name: str

    @property
    def is_dirty(self) -> bool:
        return self.primary_sequence != self.secondary_sequence

    @classmethod
    def parse(cls, data: bytes) -> "BaseBlock":
        if len(data) < BASE_BLOCK_SIZE or data[:4] != b"regf":
            raise HiveError("not a registry hive (missing 'regf' signature)")
        (seq1, seq2) = struct.unpack_from("<II", data, 4)
        ft = struct.unpack_from("<Q", data, 0x0C)[0]
        (major, minor, ftype, fformat, root, hbins) = struct.unpack_from(
            "<IIIIII", data, 0x14)
        name = data[0x30:0x30 + 64].decode("utf-16-le", "replace").split("\x00")[0]
        return cls(seq1, seq2, filetime_to_utc(ft), major, minor,
                   root, hbins, name)


@dataclass
class Cell:
    offset: int          # offset relative to the first hive bin
    allocated: bool
    data: bytes          # cell payload (after the 4-byte size field)
    signature: bytes     # first two bytes of data


class Hive:
    """Raw cell access over a hive image."""

    def __init__(self, data: bytes) -> None:
        self.raw = data
        self.base = BaseBlock.parse(data)
        self._bins_start = BASE_BLOCK_SIZE

    def cell_data(self, offset: int) -> bytes:
        """Return the payload of the cell at *offset* (relative to the first
        hive bin)."""
        pos = self._bins_start + offset
        if pos + 4 > len(self.raw):
            raise HiveError(f"cell offset {offset:#x} out of range")
        size = struct.unpack_from("<i", self.raw, pos)[0]
        length = abs(size)
        if length < 4 or pos + length > len(self.raw):
            raise HiveError(f"bad cell size at {offset:#x}")
        return self.raw[pos + 4: pos + length]

    def iter_cells(self):
        """Yield every :class:`Cell` in every hive bin (allocated and free)."""
        pos = self._bins_start
        n = len(self.raw)
        while pos + 32 <= n:
            if self.raw[pos:pos + 4] != b"hbin":
                break
            bin_size = struct.unpack_from("<I", self.raw, pos + 8)[0]
            if bin_size < HBIN_SIZE or pos + bin_size > n:
                bin_size = HBIN_SIZE
            bin_end = min(pos + bin_size, n)
            cur = pos + 32
            while cur + 4 <= bin_end:
                size = struct.unpack_from("<i", self.raw, cur)[0]
                length = abs(size)
                if length < 8 or cur + length > bin_end:
                    break
                payload = self.raw[cur + 4: cur + length]
                yield Cell(
                    offset=cur - self._bins_start,
                    allocated=size < 0,
                    data=payload,
                    signature=payload[:2],
                )
                cur += length
            pos += bin_size
