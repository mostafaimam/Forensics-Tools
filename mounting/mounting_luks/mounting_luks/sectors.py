"""Decrypt a byte range of a LUKS1 payload given the master key."""

from __future__ import annotations

from mounting_luks.essiv import cbc_essiv_decrypt
from mounting_luks.luks1 import Luks1Header

_SECTOR = 512


def decrypt_range(header: Luks1Header, master_key: bytes, image_path: str,
                  offset: int, length: int, *,
                  sector_size: int = _SECTOR) -> bytes:
    if offset % sector_size or length % sector_size:
        raise ValueError("offset and length must be sector-aligned")
    essiv_hash = header.cipher_mode.split(":", 1)[1]
    with open(image_path, "rb") as fh:
        fh.seek(offset)
        raw = fh.read(length)
    first_sector = offset // sector_size
    return cbc_essiv_decrypt(master_key, essiv_hash, raw, first_sector,
                             sector_size=sector_size)
