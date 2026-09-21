"""Forge a VeraCrypt-shaped volume header + encrypted payload for tests."""

from __future__ import annotations

import hashlib
import os
import struct
import zlib

from mounting_veracrypt import aes

PASSWORD = "Hunter2!pass"
_SALT_SIZE = 64
_HEADER_SIZE = 512
_SECTOR = 512


def build_header_blob(*, password=PASSWORD, hash_name="sha512",
                      iterations=1000, magic=b"VERA", volume_size=1 << 20,
                      master_key_scope_offset=131072,
                      encrypted_area_size=1 << 20, sector_size=512,
                      hidden_volume_size=0, tamper_crc=False,
                      master_key=None):
    salt = os.urandom(_SALT_SIZE)
    header_key = hashlib.pbkdf2_hmac(hash_name, password.encode(), salt,
                                     iterations, 64)
    key1, key2 = header_key[:32], header_key[32:64]

    dec = bytearray(_HEADER_SIZE - _SALT_SIZE)
    dec[0:4] = magic
    struct.pack_into(">HH", dec, 4, 5, 5)
    struct.pack_into(">QQQQ", dec, 28, hidden_volume_size, volume_size,
                     master_key_scope_offset, encrypted_area_size)
    struct.pack_into(">II", dec, 60, 0, sector_size)
    crc = zlib.crc32(bytes(dec[0:188])) & 0xFFFFFFFF
    if tamper_crc:
        crc ^= 0xFFFFFFFF
    struct.pack_into(">I", dec, 188, crc)

    master_key = master_key or os.urandom(64)
    dec[192:192 + 64] = master_key

    enc = aes.xts_encrypt_sector(key1, key2, 0, bytes(dec))
    blob = salt + enc
    assert len(blob) == _HEADER_SIZE
    return blob, master_key[0:32], master_key[32:64]


def build_volume(tmp_path, *, payload_sectors=4, **header_kwargs):
    blob, pkey, tkey = build_header_blob(**header_kwargs)
    hidden_blob = os.urandom(_HEADER_SIZE)  # no valid hidden volume in v0.1 tests
    master_key_scope_offset = header_kwargs.get("master_key_scope_offset",
                                                 131072)
    img = bytearray(master_key_scope_offset)
    img[0:_HEADER_SIZE] = blob
    img[_HEADER_SIZE:_HEADER_SIZE * 2] = hidden_blob

    payload_plain = b""
    for i in range(payload_sectors):
        payload_plain += (f"payload sector {i} data ".encode() * 32)[:_SECTOR]
    payload_enc = bytearray()
    for i in range(payload_sectors):
        chunk = payload_plain[i * _SECTOR:(i + 1) * _SECTOR]
        payload_enc += aes.xts_encrypt_sector(pkey, tkey, i, chunk)
    img += payload_enc

    p = tmp_path / "volume.hc"
    p.write_bytes(bytes(img))
    return str(p), master_key_scope_offset
