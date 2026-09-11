"""Forge an FVE metadata block + an encrypted volume region for tests."""

from __future__ import annotations

import os
import struct
import uuid
from datetime import datetime, timezone

from mounting_bitlocker import ccm
from mounting_bitlocker.aes import xts_encrypt_sector
from mounting_bitlocker.recovery import parse_recovery_password, stretch_key

RECOVERY_PASSWORD = "-".join(
    f"{(n * 11) % 1000000:06d}" for n in (1, 2, 3, 4, 5, 6, 7, 8))
VOL_GUID = uuid.UUID("11111111-2222-3333-4444-555555555555")


def _entry(entry_type, value_type, value: bytes) -> bytes:
    total = 8 + len(value)
    return struct.pack("<HHHH", total, entry_type, value_type, 1) + value


def build_fve(*, password=RECOVERY_PASSWORD, method_code=0x2001,
             vmk: bytes | None = None, fvek: bytes | None = None,
             tamper_vmk_tag=False):
    vmk = vmk or os.urandom(32)
    keylen = 32
    fvek = fvek or os.urandom(keylen * 2)   # XTS: key1 || key2

    salt = os.urandom(16)
    pwd_bytes = parse_recovery_password(password)
    interm = stretch_key(pwd_bytes, salt, iterations=200)  # fast for tests
    vmk_nonce = os.urandom(12)
    vmk_wrapped = bytearray(ccm.encrypt(interm, vmk_nonce, vmk))
    if tamper_vmk_tag:
        vmk_wrapped[-1] ^= 0xFF

    stretch_entry = _entry(0, 0x0003, salt)
    ccm_entry = _entry(0, 0x0005, vmk_nonce + bytes(vmk_wrapped))
    prot_value = (uuid.uuid4().bytes_le + struct.pack("<QHH", 0, 0x0002, 0)
                 + stretch_entry + ccm_entry)
    vmk_entry = _entry(0x0002, 0x0000, prot_value)

    fvek_nonce = os.urandom(12)
    fvek_wrapped = ccm.encrypt(vmk, fvek_nonce, fvek)
    fvek_entry = _entry(0x0003, 0x0005, fvek_nonce + fvek_wrapped)

    entries = vmk_entry + fvek_entry
    header = bytearray(0x30)
    header[0:8] = b"-FVE-FS-"
    struct.pack_into("<H", header, 8, 2)
    header[0x0C:0x1C] = VOL_GUID.bytes_le
    struct.pack_into("<I", header, 0x1C, 1)
    struct.pack_into("<I", header, 0x20, method_code)
    struct.pack_into("<Q", header, 0x24, 0)
    struct.pack_into("<I", header, 0x2C, len(entries))
    return bytes(header) + entries, vmk, fvek


def build_volume_image(fve_blob: bytes, fvek: bytes, *, n_sectors=4,
                       sector_size=512, method="xts"):
    """Returns (image_bytes, data_offset) - data_offset is the
    sector-aligned start of the encrypted region."""
    key1, key2 = fvek[:32], fvek[32:64]
    data_offset = ((len(fve_blob) + sector_size - 1) // sector_size) \
        * sector_size
    out = bytearray(fve_blob) + b"\x00" * (data_offset - len(fve_blob))
    first_sector = data_offset // sector_size
    for i in range(n_sectors):
        plain = (f"sector {i} plaintext data ".encode() * 32)[:sector_size]
        ct = xts_encrypt_sector(key1, key2, first_sector + i, plain)
        out += ct
    return bytes(out), data_offset
