"""Helpers to build synthetic tracev3-shaped chunk bytes and minimal
LZ4 blocks (literal-only, or with one match) for tests."""

from __future__ import annotations

import struct


def chunk_bytes(tag: int, payload: bytes, sub_tag: int = 0) -> bytes:
    header = struct.pack("<IIQ", tag, sub_tag, len(payload))
    body = header + payload
    pad = (-len(body)) % 8
    return body + b"\x00" * pad


def lz4_literal_only_block(data: bytes) -> bytes:
    """A valid LZ4 block containing only a literal run - no matches."""
    out = bytearray()
    length = len(data)
    if length < 15:
        out.append(length << 4)
    else:
        out.append(0xF0)
        remaining = length - 15
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    out += data
    return bytes(out)


def lz4_block_with_match(literal: bytes, match_offset: int,
                         match_length: int) -> bytes:
    """literal run, then one match copying `match_length` bytes from
    `match_offset` bytes back in the output. `match_length` must be
    >= 4 (LZ4's minimum)."""
    assert match_length >= 4
    out = bytearray()
    lit_len = len(literal)
    ml = match_length - 4
    lit_nibble = min(lit_len, 0x0F)
    ml_nibble = min(ml, 0x0F)
    out.append((lit_nibble << 4) | ml_nibble)
    if lit_len >= 0x0F:
        remaining = lit_len - 0x0F
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    out += literal
    out += struct.pack("<H", match_offset)
    if ml >= 0x0F:
        remaining = ml - 0x0F
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    return bytes(out)
