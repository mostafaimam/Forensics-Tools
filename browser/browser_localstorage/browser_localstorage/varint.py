"""LevelDB's little-endian base-128 varint encoding (same shape as
protobuf varints): 7 payload bits per byte, high bit = "more follows"."""

from __future__ import annotations


class VarintError(ValueError):
    pass


def decode(buf: bytes, offset: int) -> tuple[int, int]:
    """Return (value, new_offset)."""
    result = 0
    shift = 0
    pos = offset
    while True:
        if pos >= len(buf):
            raise VarintError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise VarintError("varint too long")


def encode(value: int) -> bytes:
    if value < 0:
        raise VarintError("varint must be non-negative")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)
