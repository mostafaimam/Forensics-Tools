"""Build a LiME dump with known strings at known physical addresses."""

from __future__ import annotations

import struct

_LIME = struct.Struct("<IIQQQ")


def lime_with(placements: dict) -> bytes:
    """placements: {phys_addr: bytes} - each placed inside one run [0, size)."""
    size = max(a + len(b) for a, b in placements.items()) + 0x1000
    size = (size + 0xFFF) & ~0xFFF
    ram = bytearray(size)
    for addr, data in placements.items():
        ram[addr:addr + len(data)] = data
    out = bytearray()
    out += _LIME.pack(0x4C694D45, 1, 0, size - 1, 0)
    out += ram
    return bytes(out)


def u16(s: str) -> bytes:
    return s.encode("utf-16-le")
