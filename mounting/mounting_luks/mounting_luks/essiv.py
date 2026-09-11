"""ESSIV sector-IV derivation (dm-crypt's "cbc-essiv:<hash>" cipher mode)."""

from __future__ import annotations

import hashlib

from mounting_luks import aes


def _essiv_key(cipher_key: bytes, hash_name: str) -> bytes:
    return hashlib.new(hash_name, cipher_key).digest()


def _iv(essiv_key: bytes, sector_index: int) -> bytes:
    block = sector_index.to_bytes(16, "little")
    return aes.encrypt_ecb(essiv_key, block)


def cbc_essiv_decrypt(cipher_key: bytes, hash_name: str, data: bytes,
                      first_sector: int, *, sector_size: int = 512) -> bytes:
    essiv_key = _essiv_key(cipher_key, hash_name)
    out = bytearray()
    for i in range(0, len(data), sector_size):
        iv = _iv(essiv_key, first_sector + i // sector_size)
        out += aes.decrypt_cbc(cipher_key, iv, data[i:i + sector_size])
    return bytes(out)


def cbc_essiv_encrypt(cipher_key: bytes, hash_name: str, data: bytes,
                      first_sector: int, *, sector_size: int = 512) -> bytes:
    essiv_key = _essiv_key(cipher_key, hash_name)
    out = bytearray()
    for i in range(0, len(data), sector_size):
        iv = _iv(essiv_key, first_sector + i // sector_size)
        out += aes.encrypt_cbc(cipher_key, iv, data[i:i + sector_size])
    return bytes(out)
