"""EVTX file- and chunk-level structures.

File header (4096 bytes, only the first 128 used)::

    0x00  8   "ElfFile\x00"
    0x08  u64 first chunk number
    0x10  u64 last chunk number
    0x18  u64 next record identifier
    0x20  u32 header size (128)
    0x24  u16 minor version (1)
    0x26  u16 major version (3)
    0x28  u16 header block size (4096)
    0x2a  u16 number of chunks
    0x78  u32 flags   (0x1 = dirty, 0x2 = full)
    0x7c  u32 CRC32 checksum of the first 120 bytes

Chunk header (512 bytes)::

    0x00  8   "ElfChnk\x00"
    0x08  u64 first event record number
    0x10  u64 last event record number
    0x18  u64 first event record identifier
    0x20  u64 last event record identifier
    0x28  u32 header size (128)
    0x2c  u32 last record data offset  (relative to chunk start)
    0x30  u32 free space offset
    0x34  u32 CRC32 of the event records data
    0x80  64 x u32  name-string bucket offsets
    0x180 32 x u32  template bucket offsets
    0x1fc u32 CRC32 checksum

Event records start at chunk offset 512::

    0x00  u32  magic 0x00002a2a
    0x04  u32  size
    0x08  u64  event record identifier
    0x10  u64  written time (FILETIME, UTC)
    0x18  ..   BinXML fragment
    end   u32  copy of size
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

FILE_SIGNATURE = b"ElfFile\x00"
CHUNK_SIGNATURE = b"ElfChnk\x00"
RECORD_MAGIC = 0x00002A2A
CHUNK_SIZE = 65536
FILE_HEADER_SIZE = 4096
CHUNK_DATA_OFFSET = 512


class EvtxError(ValueError):
    pass


@dataclass
class FileHeader:
    first_chunk: int
    last_chunk: int
    next_record_id: int
    chunk_count: int
    major_version: int
    minor_version: int
    is_dirty: bool
    is_full: bool

    @classmethod
    def parse(cls, data: bytes) -> "FileHeader":
        if len(data) < 128 or data[:8] != FILE_SIGNATURE:
            raise EvtxError("not an EVTX file (missing 'ElfFile' signature)")
        (first_chunk, last_chunk, next_rec) = struct.unpack_from("<QQQ", data, 8)
        (hdr_size, minor, major, block, n_chunks) = struct.unpack_from(
            "<IHHHH", data, 0x20)
        flags = struct.unpack_from("<I", data, 0x78)[0]
        return cls(
            first_chunk=first_chunk, last_chunk=last_chunk,
            next_record_id=next_rec, chunk_count=n_chunks,
            major_version=major, minor_version=minor,
            is_dirty=bool(flags & 0x1), is_full=bool(flags & 0x2),
        )


@dataclass
class ChunkHeader:
    first_record_number: int
    last_record_number: int
    first_record_id: int
    last_record_id: int
    last_record_offset: int
    free_space_offset: int

    @classmethod
    def parse(cls, data: bytes) -> "ChunkHeader":
        if len(data) < 512 or data[:8] != CHUNK_SIGNATURE:
            raise EvtxError("bad chunk signature")
        (frn, lrn, fri, lri) = struct.unpack_from("<QQQQ", data, 8)
        (hdr_size, last_off, free_off) = struct.unpack_from("<III", data, 0x28)
        return cls(frn, lrn, fri, lri, last_off, free_off)


@dataclass
class RawRecord:
    identifier: int
    timestamp_filetime: int
    chunk_number: int
    binxml_offset: int      # chunk-relative offset of the BinXML fragment
    size: int
    offset: int             # absolute file offset of the record


def iter_chunks(data: bytes):
    """Yield (chunk_number, chunk_bytes) for every valid chunk."""
    n = len(data)
    off = FILE_HEADER_SIZE
    number = 0
    while off + CHUNK_SIZE <= n + 1:
        block = data[off:off + CHUNK_SIZE]
        if len(block) < 512 or block[:8] != CHUNK_SIGNATURE:
            break
        yield number, block
        number += 1
        off += CHUNK_SIZE


def iter_records(chunk_number: int, chunk: bytes, file_offset: int):
    """Yield RawRecord for every event record in a chunk."""
    off = CHUNK_DATA_OFFSET
    n = len(chunk)
    while off + 24 <= n:
        magic, size = struct.unpack_from("<II", chunk, off)
        if magic != RECORD_MAGIC:
            break
        if size < 24 or off + size > n:
            break
        rec_id, ts = struct.unpack_from("<QQ", chunk, off + 8)
        yield RawRecord(
            identifier=rec_id, timestamp_filetime=ts,
            chunk_number=chunk_number, binxml_offset=off + 24, size=size,
            offset=file_offset + off,
        )
        off += size + (-size % 8)
