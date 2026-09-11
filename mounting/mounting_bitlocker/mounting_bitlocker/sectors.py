"""Decrypt a byte range of a BitLocker-encrypted volume given its keys."""

from __future__ import annotations

from mounting_bitlocker import aes


def decrypt_range(unlocked, image_path: str, offset: int, length: int, *,
                  sector_size: int = 512) -> bytes:
    if offset % sector_size or length % sector_size:
        raise ValueError("offset and length must be sector-aligned")
    with open(image_path, "rb") as fh:
        fh.seek(offset)
        raw = fh.read(length)
    out = bytearray()
    method = unlocked.method
    for i in range(0, len(raw), sector_size):
        sector_index = (offset + i) // sector_size
        chunk = raw[i:i + sector_size]
        if "xts" in method:
            out += aes.xts_decrypt_sector(unlocked.key1, unlocked.key2,
                                          sector_index, chunk)
        elif "cbc" in method:
            # BitLocker CBC mode derives a per-sector IV by AES-encrypting
            # the sector number with the FVEK itself (no separate tweak
            # key); the "Elephant diffuser" post-processing used on some
            # older volumes is not implemented here (see README).
            iv = aes.encrypt_ecb(unlocked.key1,
                                 sector_index.to_bytes(16, "little"))
            out += aes.decrypt_cbc(unlocked.key1, iv, chunk)
        else:
            raise ValueError(f"unsupported method for sector decrypt: "
                             f"{method}")
    return bytes(out)
