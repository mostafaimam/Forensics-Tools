"""CRC-32C (Castagnoli) - the checksum LevelDB uses for every log record
and every SSTable block, plus its "masked" wrapper.

LevelDB never stores a raw CRC32C: it applies ``mask()`` before writing
and ``unmask()`` before comparing, per the upstream ``crc32c::Mask``
convention (rotate right 15 + a fixed delta) - reportedly to avoid
flagging a stored CRC as valid-looking data during recovery scans.
"""

from __future__ import annotations

_POLY = 0x82F63B78  # reversed Castagnoli polynomial
_MASK_DELTA = 0xA282EAD8


def _make_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ _POLY if c & 1 else c >> 1
        table.append(c)
    return table


_TABLE = _make_table()


def crc32c(data: bytes, crc: int = 0) -> int:
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = _TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def mask(crc: int) -> int:
    return (((crc >> 15) | (crc << 17)) + _MASK_DELTA) & 0xFFFFFFFF


def unmask(masked: int) -> int:
    rot = (masked - _MASK_DELTA) & 0xFFFFFFFF
    return ((rot >> 17) | (rot << 15)) & 0xFFFFFFFF
