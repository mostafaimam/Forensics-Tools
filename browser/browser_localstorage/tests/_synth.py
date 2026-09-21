"""Build real .log and .ldb files matching LevelDB's on-disk formats."""

from __future__ import annotations

import struct
from pathlib import Path

from browser_localstorage import crc32c
from browser_localstorage.varint import encode as v

_MAGIC = struct.pack("<Q", 0xDB4775248B80FB57)

_TYPE_FULL = 1
_TAG_VALUE, _TAG_DELETION = 1, 0


def _crc_for(rtype: int, payload: bytes) -> int:
    return crc32c.mask(crc32c.crc32c(payload, crc32c.crc32c(bytes([rtype]))))


def write_log(path: Path, batches: list[tuple[int, list[tuple[str, bytes,
                                                              bytes | None]]]]) -> None:
    """batches: [(sequence, [(tag, key, value_or_none), ...]), ...]"""
    out = bytearray()
    for seq, entries in batches:
        body = bytearray()
        for tag, key, value in entries:
            if tag == "value":
                body += bytes([_TAG_VALUE]) + v(len(key)) + key + \
                    v(len(value)) + value
            else:
                body += bytes([_TAG_DELETION]) + v(len(key)) + key
        record = struct.pack("<Q", seq) + struct.pack("<I", len(entries)) \
            + bytes(body)
        crc = _crc_for(_TYPE_FULL, record)
        out += struct.pack("<I", crc) + struct.pack("<H", len(record)) + \
            bytes([_TYPE_FULL]) + record
    path.write_bytes(bytes(out))


def _wrap_block(contents: bytes, compression_type: int = 0) -> bytes:
    crc = crc32c.mask(
        crc32c.crc32c(bytes([compression_type]), crc32c.crc32c(contents)))
    return contents + bytes([compression_type]) + struct.pack("<I", crc)


def _block_from_entries(entries: list[tuple[bytes, bytes]]) -> bytes:
    """entries: [(key, value), ...], every entry a restart point (shared=0)."""
    body = bytearray()
    restarts = []
    for key, value in entries:
        restarts.append(len(body))
        body += v(0) + v(len(key)) + v(len(value)) + key + value
    for off in restarts:
        body += struct.pack("<I", off)
    body += struct.pack("<I", len(restarts))
    return bytes(body)


def write_sstable(path: Path, records: list[tuple[bytes, int, bool, bytes]],
                  compress: bool = False) -> None:
    """records: [(user_key, sequence, deleted, value), ...]"""
    data_entries = []
    for user_key, seq, deleted, value in records:
        vtype = 0 if deleted else 1
        ikey = user_key + struct.pack("<Q", (seq << 8) | vtype)
        data_entries.append((ikey, b"" if deleted else value))
    data_contents = _block_from_entries(data_entries)
    if compress:
        from tests._snappy_encode import compress_literal_only
        raw = compress_literal_only(data_contents)
        ctype = 1
    else:
        raw = data_contents
        ctype = 0
    data_on_disk = _wrap_block(raw, ctype)

    handle = v(0) + v(len(raw))
    index_contents = _block_from_entries([(b"\xff\xff\xff\xff", handle)])
    index_on_disk = _wrap_block(index_contents, 0)

    footer_body = bytearray()
    footer_body += v(0) + v(0)                       # metaindex handle (unused)
    footer_body += v(len(data_on_disk)) + v(len(index_contents))
    footer_body = footer_body.ljust(40, b"\x00")
    footer = bytes(footer_body) + _MAGIC

    path.write_bytes(data_on_disk + index_on_disk + footer)


def local_storage_key(origin: str, js_key: str) -> bytes:
    return b"_" + origin.encode() + b"\x00" + js_key.encode()


def local_storage_value(text: str, utf16: bool = True) -> bytes:
    if utf16:
        return bytes([0]) + text.encode("utf-16-le")
    return bytes([1]) + text.encode("latin-1")
