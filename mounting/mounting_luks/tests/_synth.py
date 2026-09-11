"""Forge a LUKS1 header + encrypted key slot + payload for tests."""

from __future__ import annotations

import hashlib
import os
import struct

from mounting_luks.af import af_split
from mounting_luks.essiv import cbc_essiv_encrypt

PASSPHRASE = "Hunter2!pass"
_SECTOR = 512


def build_volume(*, key_bytes=32, stripes=64, iterations=200,
                 mk_digest_iterations=200, master_key: bytes | None = None,
                 payload_sectors=4, hash_spec="sha256", tamper_digest=False):
    master_key = master_key or os.urandom(key_bytes)
    cipher_mode = f"cbc-essiv:{hash_spec}"

    salt = os.urandom(32)
    slot_key = hashlib.pbkdf2_hmac(hash_spec, PASSPHRASE.encode(), salt,
                                   iterations, key_bytes)
    split = af_split(master_key, stripes)
    material_len = stripes * key_bytes
    assert material_len % _SECTOR == 0, "keep the test fixture sector-aligned"
    key_material_sector = 8       # arbitrary, after the header
    encrypted_material = cbc_essiv_encrypt(slot_key, hash_spec, split,
                                           key_material_sector)

    mk_digest_salt = os.urandom(32)
    mk_digest = hashlib.pbkdf2_hmac(hash_spec, master_key, mk_digest_salt,
                                    mk_digest_iterations, 20)
    if tamper_digest:
        mk_digest = bytes([mk_digest[0] ^ 0xFF]) + mk_digest[1:]

    payload_sector = key_material_sector + material_len // _SECTOR
    header = bytearray(0x250)
    header[0:6] = b"LUKS\xba\xbe"
    struct.pack_into(">H", header, 6, 1)
    header[0x08:0x08 + 3] = b"aes"
    header[0x28:0x28 + len(cipher_mode)] = cipher_mode.encode()
    header[0x48:0x48 + len(hash_spec)] = hash_spec.encode()
    struct.pack_into(">I", header, 0x68, payload_sector)
    struct.pack_into(">I", header, 0x6C, key_bytes)
    header[0x70:0x84] = mk_digest.ljust(20, b"\x00")[:20]
    header[0x84:0xA4] = mk_digest_salt
    struct.pack_into(">I", header, 0xA4, mk_digest_iterations)
    uuid_str = "11111111-2222-3333-4444-555555555555"
    header[0xA8:0xA8 + len(uuid_str)] = uuid_str.encode()

    # slot 0: active; slot 1: inactive
    off0 = 0xD0
    struct.pack_into(">II", header, off0, 0x00AC71F3, iterations)
    header[off0 + 8:off0 + 40] = salt
    struct.pack_into(">II", header, off0 + 40, key_material_sector, stripes)

    off1 = 0xD0 + 48
    struct.pack_into(">II", header, off1, 0x0000DEAD, 0)

    img = bytearray(payload_sector * _SECTOR)
    img[:len(header)] = header
    km_off = key_material_sector * _SECTOR
    img[km_off:km_off + len(encrypted_material)] = encrypted_material

    payload_plain = b""
    payload_enc = b""
    for i in range(payload_sectors):
        chunk = (f"payload sector {i} data ".encode() * 32)[:_SECTOR]
        payload_plain += chunk
    payload_enc = cbc_essiv_encrypt(master_key, hash_spec, payload_plain,
                                    payload_sector)
    img += payload_enc
    return bytes(img), master_key, payload_sector * _SECTOR
