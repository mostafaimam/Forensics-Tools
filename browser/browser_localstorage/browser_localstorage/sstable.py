"""Reader for LevelDB SSTable (.ldb) files.

Layout: a sequence of ~4 KiB data blocks, an index block (separator key
-> BlockHandle of a data block), a metaindex block (unused here), and a
fixed 48-byte footer (metaindex handle + index handle + magic number).
Each on-disk block is [contents][compression_type: 1 byte][masked
crc32c: 4 bytes LE]; contents are Snappy-compressed unless
compression_type is 0. A block's *contents* are a sequence of
front-coded (shared-prefix) key/value entries followed by a restart-
point array and a restart count.

The keys stored in a *data* block are "internal keys": the real user
key with an 8-byte little-endian trailer packing
``(sequence_number << 8) | value_type`` (0 = deletion, 1 = value).
"""

from __future__ import annotations

import struct

from browser_localstorage import crc32c, snappy
from browser_localstorage.record import Record
from browser_localstorage.varint import decode as _varint

_MAGIC = struct.pack("<Q", 0xDB4775248B80FB57)


class SstableError(ValueError):
    pass


def _parse_footer(data: bytes):
    if len(data) < 48:
        raise SstableError("file too short for a footer")
    footer = data[-48:]
    if footer[-8:] != _MAGIC:
        raise SstableError("bad SSTable magic number")
    body = footer[:-8]
    meta_off, pos = _varint(body, 0)
    meta_size, pos = _varint(body, pos)
    idx_off, pos = _varint(body, pos)
    idx_size, pos = _varint(body, pos)
    return (meta_off, meta_size), (idx_off, idx_size)


def _read_block(data: bytes, offset: int, size: int) -> bytes:
    end = offset + size
    if end + 5 > len(data) or offset < 0:
        raise SstableError("block handle out of range")
    raw = data[offset:end]
    trailer = data[end:end + 5]
    ctype = trailer[0]
    stored_crc = int.from_bytes(trailer[1:5], "little")
    computed = crc32c.mask(
        crc32c.crc32c(bytes([ctype]), crc32c.crc32c(raw)))
    if computed != stored_crc:
        raise SstableError("block checksum mismatch")
    if ctype == 0:
        return raw
    if ctype == 1:
        return snappy.decompress(raw)
    raise SstableError(f"unsupported block compression type {ctype}")


def _read_block_entries(contents: bytes):
    if len(contents) < 4:
        return
    num_restarts = int.from_bytes(contents[-4:], "little")
    restart_area = len(contents) - 4 - 4 * num_restarts
    if restart_area < 0:
        raise SstableError("bad restart count")
    pos = 0
    prev_key = b""
    while pos < restart_area:
        shared, pos = _varint(contents, pos)
        non_shared, pos = _varint(contents, pos)
        vlen, pos = _varint(contents, pos)
        key_delta = contents[pos:pos + non_shared]
        pos += non_shared
        value = contents[pos:pos + vlen]
        pos += vlen
        key = prev_key[:shared] + key_delta
        prev_key = key
        yield key, value


def _split_internal_key(ikey: bytes) -> tuple[bytes, int, bool]:
    if len(ikey) < 8:
        raise SstableError("internal key too short")
    tail = int.from_bytes(ikey[-8:], "little")
    return ikey[:-8], tail >> 8, (tail & 0xFF) == 0


def read(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    (_meta_off, _meta_size), (idx_off, idx_size) = _parse_footer(data)
    index_contents = _read_block(data, idx_off, idx_size)
    for _sep_key, handle in _read_block_entries(index_contents):
        try:
            d_off, p = _varint(handle, 0)
            d_size, _p = _varint(handle, p)
            block_contents = _read_block(data, d_off, d_size)
        except (SstableError, snappy.SnappyError):
            continue
        for ikey, value in _read_block_entries(block_contents):
            try:
                user_key, seq, deleted = _split_internal_key(ikey)
            except SstableError:
                continue
            yield Record(path, "sstable", seq, deleted,
                        user_key, b"" if deleted else value)
