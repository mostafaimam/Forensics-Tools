"""Reader for LevelDB's write-ahead log (.log) files.

A .log file is a sequence of 32 KiB blocks. Each block holds physical
records: crc32c(4, masked) + length(2, LE) + type(1) + data, where type
is FULL(1) / FIRST(2) / MIDDLE(3) / LAST(4); FIRST..MIDDLE*..LAST spans
reassemble one logical record. A logical record is a serialized
WriteBatch: sequence(8, LE) + count(4, LE), then `count` entries of
tag(1: 0=deletion,1=value) + varint(key_len) + key + [varint(value_len)
+ value] for value entries.
"""

from __future__ import annotations

from browser_localstorage import crc32c
from browser_localstorage.record import Record
from browser_localstorage.varint import decode as _varint

_BLOCK_SIZE = 32768
_HEADER_SIZE = 7
_TYPE_FULL, _TYPE_FIRST, _TYPE_MIDDLE, _TYPE_LAST = 1, 2, 3, 4


def _physical_records(data: bytes):
    """Yield (type, payload, crc_ok) physical records across all blocks."""
    pos = 0
    n = len(data)
    while pos < n:
        block_end = min(pos + _BLOCK_SIZE, n)
        bpos = pos
        while bpos + _HEADER_SIZE <= block_end:
            stored_crc = int.from_bytes(data[bpos:bpos + 4], "little")
            length = int.from_bytes(data[bpos + 4:bpos + 6], "little")
            rtype = data[bpos + 6]
            payload_start = bpos + _HEADER_SIZE
            payload_end = payload_start + length
            if rtype == 0 or payload_end > block_end:
                break  # zero padding / trailer
            payload = data[payload_start:payload_end]
            computed = crc32c.mask(
                crc32c.crc32c(payload, crc32c.crc32c(bytes([rtype]))))
            yield rtype, payload, computed == stored_crc
            bpos = payload_end
        pos = block_end


def _logical_records(data: bytes):
    """Reassemble physical FIRST/MIDDLE/LAST spans into full records."""
    buf = bytearray()
    in_progress = False
    for rtype, payload, crc_ok in _physical_records(data):
        if rtype == _TYPE_FULL:
            yield bytes(payload), crc_ok
            in_progress = False
        elif rtype == _TYPE_FIRST:
            buf = bytearray(payload)
            in_progress = True
        elif rtype == _TYPE_MIDDLE and in_progress:
            buf += payload
        elif rtype == _TYPE_LAST and in_progress:
            buf += payload
            yield bytes(buf), crc_ok
            in_progress = False
        # a MIDDLE/LAST with no preceding FIRST is a torn record; skipped


_TAG_DELETION, _TAG_VALUE = 0, 1


def _write_batch_entries(seq: int, body: bytes):
    pos = 0
    idx = 0
    n = len(body)
    while pos < n:
        tag = body[pos]
        pos += 1
        klen, pos = _varint(body, pos)
        key = body[pos:pos + klen]
        pos += klen
        if tag == _TAG_VALUE:
            vlen, pos = _varint(body, pos)
            value = body[pos:pos + vlen]
            pos += vlen
            yield Record("", "log", seq + idx, False, key, value)
        elif tag == _TAG_DELETION:
            yield Record("", "log", seq + idx, True, key, b"")
        else:
            return  # unknown tag; stop this batch rather than misparse
        idx += 1


def read(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    for body, crc_ok in _logical_records(data):
        if len(body) < 12 or not crc_ok:
            continue
        seq = int.from_bytes(body[0:8], "little")
        count = int.from_bytes(body[8:12], "little")
        try:
            entries = list(_write_batch_entries(seq, body[12:]))
        except (IndexError, ValueError):
            continue
        for e in entries[:count] if count else entries:
            e.source = path
            yield e
