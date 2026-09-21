"""Decrypt a byte range of a VeraCrypt volume's encrypted area."""

from __future__ import annotations

from mounting_veracrypt import aes
from mounting_veracrypt.header import Header


def decrypt_range(header: Header, image_path: str, offset: int,
                  length: int) -> bytes:
    sector_size = header.effective_sector_size
    if offset % sector_size or length % sector_size:
        raise ValueError("offset and length must be sector-aligned")
    if offset < header.master_key_scope_offset:
        raise ValueError("offset is before the start of the encrypted area")
    with open(image_path, "rb") as fh:
        fh.seek(offset)
        raw = fh.read(length)
    out = bytearray()
    base_unit = (offset - header.master_key_scope_offset) // sector_size
    for i in range(0, len(raw), sector_size):
        unit = base_unit + i // sector_size
        out += aes.xts_decrypt_sector(header.primary_key, header.tweak_key,
                                      unit, raw[i:i + sector_size])
    return bytes(out)
