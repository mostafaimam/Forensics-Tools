"""Build a synthetic dirty hive + a matching transaction log."""

from __future__ import annotations

import struct

from windows_reglog.marvin32 import marvin32

BASE = 4096
LOG_BASE = 512
HBIN = 4096


def _regf_base(seq1: int, seq2: int, file_type: int, hbins: int,
               size: int = BASE) -> bytearray:
    b = bytearray(size)
    b[0:4] = b"regf"
    struct.pack_into("<II", b, 4, seq1, seq2)
    struct.pack_into("<I", b, 0x1C, file_type)
    struct.pack_into("<IIII", b, 0x14, 1, 5, file_type, 1)
    struct.pack_into("<I", b, 0x24, 0x20)          # root cell offset
    struct.pack_into("<I", b, 0x28, hbins)
    # XOR-32 checksum of the first 508 bytes
    csum = 0
    for i in range(0, 508, 4):
        csum ^= struct.unpack_from("<I", b, i)[0]
    struct.pack_into("<I", b, 0x1FC, csum or 1)
    return b


def _hbin(marker: bytes) -> bytearray:
    h = bytearray(HBIN)
    h[0:4] = b"hbin"
    struct.pack_into("<II", h, 4, 0, HBIN)
    h[0x20:0x20 + len(marker)] = marker
    return h


def build_primary(seq1: int, seq2: int, marker: bytes = b"ORIGINAL-PAGE") -> bytes:
    base = _regf_base(seq1, seq2, 0, HBIN)
    return bytes(base) + bytes(_hbin(marker))


def build_log(seq: int, page_offset: int, page_data: bytes,
              hbins_after: int = HBIN) -> bytes:
    page = page_data.ljust(HBIN, b"\x00")[:HBIN]
    count = 1
    refs = struct.pack("<II", page_offset, len(page))
    body = struct.pack("<I", hbins_after) + struct.pack("<I", count) + b""
    # HvLE header: sig(4) size(4) flags(4) seq(4) hbins(4) count(4) h1(8) h2(8)
    #   then refs, then page data
    payload = refs + page
    entry_size = 0x28 + len(payload)
    entry_size = (entry_size + 511) & ~511
    pad = entry_size - 0x28 - len(payload)

    header_wo_hash = struct.pack("<4sIIIII", b"HvLE", entry_size, 0, seq,
                                 hbins_after, count)
    # body for hash-1 = everything from 0x28 onwards (refs + page + pad)
    body_bytes = payload + b"\x00" * pad
    h1 = marvin32(body_bytes)
    # hash-2 = first 0x20 bytes (header up to and including the start of h1);
    #   with h1 present, that is header_wo_hash (24) + first 8 bytes of h1.
    prefix = header_wo_hash + struct.pack("<Q", h1)[:8]
    h2 = marvin32(prefix[:0x20])

    entry = header_wo_hash + struct.pack("<QQ", h1, h2) + body_bytes

    logbase = _regf_base(seq, seq, 1, hbins_after, LOG_BASE)
    return bytes(logbase) + bytes(entry)
