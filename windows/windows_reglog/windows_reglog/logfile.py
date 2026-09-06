r"""Parse a registry hive base block and the "new format" (Windows 8.1+)
transaction-log entries.

Base block (4096 bytes)::

    0x00  4   "regf"
    0x04  u32 primary sequence number
    0x08  u32 secondary sequence number
    0x1c  u32 file type   (0 = primary hive, 1 = transaction log)
    0x24  u32 root cell offset
    0x28  u32 hive bins data size
    0x1fc u32 XOR-32 checksum of the first 508 bytes

Log entry ``HvLE`` (each starts on a 512-byte boundary, first at 0x1000)::

    0x00  4   "HvLE"
    0x04  u32 log entry size (header + dirty-page refs + page data, /512)
    0x08  u32 flags
    0x0c  u32 sequence number
    0x10  u32 hive bins data size after this entry is applied
    0x14  u32 dirty page count
    0x18  u64 hash-1  (Marvin32 of everything from 0x28 onwards)
    0x20  u64 hash-2  (Marvin32 of bytes 0x00..0x27)
    0x28  ..  dirty page refs: count x { u32 offset (rel. to hbins), u32 size }
    ...       the dirty page data, concatenated
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from windows_reglog.marvin32 import marvin32

BASE_BLOCK_SIZE = 4096       # primary hive base block
LOG_BASE_BLOCK_SIZE = 512    # transaction-log base block
LOG_ENTRY_START = 512
HVLE = b"HvLE"


class RegLogError(ValueError):
    pass


@dataclass
class BaseBlock:
    raw: bytes
    primary_sequence: int
    secondary_sequence: int
    file_type: int
    hive_bins_size: int

    @property
    def is_log(self) -> bool:
        return self.file_type != 0

    @property
    def is_dirty(self) -> bool:
        return self.primary_sequence != self.secondary_sequence

    @classmethod
    def parse(cls, data: bytes) -> "BaseBlock":
        if len(data) < LOG_BASE_BLOCK_SIZE or data[:4] != b"regf":
            raise RegLogError("missing 'regf' signature")
        seq1, seq2 = struct.unpack_from("<II", data, 4)
        ftype = struct.unpack_from("<I", data, 0x1C)[0]
        hbins = struct.unpack_from("<I", data, 0x28)[0]
        return cls(data[:BASE_BLOCK_SIZE], seq1, seq2, ftype, hbins)


@dataclass
class DirtyPage:
    offset: int          # relative to the start of the hive bins
    size: int
    data: bytes


@dataclass
class LogEntry:
    sequence: int
    entry_size: int
    flags: int
    hive_bins_size: int
    pages: list[DirtyPage] = field(default_factory=list)
    hash1_ok: bool = False
    hash2_ok: bool = False


def parse_log(data: bytes) -> tuple[BaseBlock, list[LogEntry]]:
    base = BaseBlock.parse(data)
    entries: list[LogEntry] = []
    pos = LOG_ENTRY_START
    n = len(data)
    while pos + 0x28 <= n:
        if data[pos:pos + 4] != HVLE:
            break
        size = struct.unpack_from("<I", data, pos + 4)[0]
        if size < 0x28 or size % 512 or pos + size > n:
            break
        flags = struct.unpack_from("<I", data, pos + 8)[0]
        seq = struct.unpack_from("<I", data, pos + 0x0C)[0]
        hbins = struct.unpack_from("<I", data, pos + 0x10)[0]
        count = struct.unpack_from("<I", data, pos + 0x14)[0]
        stored_h1 = struct.unpack_from("<Q", data, pos + 0x18)[0]
        stored_h2 = struct.unpack_from("<Q", data, pos + 0x20)[0]

        refs_end = 0x28 + count * 8
        if pos + refs_end > pos + size:
            break
        refs = [struct.unpack_from("<II", data, pos + 0x28 + i * 8)
                for i in range(count)]

        page_area = data[pos + refs_end: pos + size]
        cursor = 0
        pages = []
        for off, psize in refs:
            chunk = page_area[cursor:cursor + psize]
            cursor += psize
            pages.append(DirtyPage(off, psize, chunk))

        entry = LogEntry(seq, size, flags, hbins, pages)
        body = data[pos + 0x28: pos + size]
        head = data[pos: pos + 0x28 - 16]        # bytes 0x00..0x17
        try:
            entry.hash1_ok = marvin32(body) == stored_h1
            entry.hash2_ok = marvin32(data[pos:pos + 0x20]) == stored_h2 \
                or marvin32(head) == stored_h2
        except Exception:  # noqa: BLE001
            pass
        entries.append(entry)
        pos += size
    return base, entries
