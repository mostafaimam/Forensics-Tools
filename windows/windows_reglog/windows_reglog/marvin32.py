"""Marvin32 hash - used to authenticate registry transaction-log entries.

The seed Windows uses for hive log entries is the constant below.
"""

from __future__ import annotations

import struct

LOG_SEED = 0x82EF4D887A4E55C5
_M32 = 0xFFFFFFFF


def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _M32


def _mix(lo: int, hi: int, data: int) -> tuple[int, int]:
    lo = (lo + data) & _M32
    hi ^= lo
    lo = _rotl(lo, 20)
    lo = (lo + hi) & _M32
    hi = _rotl(hi, 9)
    hi ^= lo
    lo = _rotl(lo, 27)
    lo = (lo + hi) & _M32
    hi = _rotl(hi, 19)
    return lo, hi


def marvin32(data: bytes, seed: int = LOG_SEED) -> int:
    lo = seed & _M32
    hi = (seed >> 32) & _M32

    n = len(data)
    full = n & ~3
    for i in range(0, full, 4):
        lo, hi = _mix(lo, hi, struct.unpack_from("<I", data, i)[0])

    # trailing 0-3 bytes + the 0x80 end marker
    tail = data[full:]
    final = 0x80
    for b in reversed(tail):
        final = (final << 8) | b
    lo, hi = _mix(lo, hi, final)
    lo, hi = _mix(lo, hi, 0)

    return (hi << 32) | lo
