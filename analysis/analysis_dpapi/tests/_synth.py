"""Forge a DPAPI master-key file and a data blob for a known password/SID."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import uuid

from analysis_dpapi.aes import encrypt_cbc

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
PASSWORD = "Hunter2!pass"
MK_GUID = "3e1b2c4d-5f60-7a80-9bc0-de01f23456aa"


def _prekey(password=PASSWORD, sid=SID):
    ph = hashlib.sha1(password.encode("utf-16-le")).digest()
    return hmac.new(ph, (sid + "\0").encode("utf-16-le"),
                    hashlib.sha1).digest()


def build_masterkey_file(*, rounds=4000, masterkey: bytes | None = None):
    masterkey = masterkey or os.urandom(64)
    prekey = _prekey()
    salt = os.urandom(16)
    hmac_salt = os.urandom(16)
    outer = hmac.new(prekey, hmac_salt, hashlib.sha512).digest()
    given = hmac.new(outer, masterkey, hashlib.sha512).digest()
    cleartext = hmac_salt + given + masterkey            # 16 + 64 + 64 = 144
    material = hashlib.pbkdf2_hmac("sha512", prekey, salt, rounds, 48)
    ct = encrypt_cbc(material[:32], material[32:48], cleartext)

    blob = struct.pack("<I", 2) + salt + struct.pack("<III", rounds,
                                                     0x800E, 0x6610) + ct
    guid_utf16 = MK_GUID.encode("utf-16-le").ljust(72, b"\x00")
    hdr = struct.pack("<I", 2) + b"\x00" * 8 + guid_utf16
    hdr += b"\x00" * 8 + struct.pack("<I", 0)            # 2xu32 unk + policy
    hdr += struct.pack("<QQQQ", len(blob), 0, 0, 0)
    return hdr + blob, masterkey


_PROVIDER = uuid.UUID("df9d8cd0-1501-11d1-8c7a-00c04fc297eb").bytes_le


def build_blob(masterkey: bytes, plaintext: bytes, *, description="cookie",
               entropy: bytes | None = None):
    salt = os.urandom(16)
    hmac_key = os.urandom(16)
    mac = hmac.new(masterkey, salt, hashlib.sha512)
    if entropy:
        mac.update(entropy)
    session_key = mac.digest()
    # deriveKey: sessionKey(64) <= blockSize(128) -> ipad/opad expansion
    ipad = bytearray(b"\x36" * 128)
    opad = bytearray(b"\x5c" * 128)
    for i, bb in enumerate(session_key):
        ipad[i] ^= bb
        opad[i] ^= bb
    derived = (hashlib.sha512(bytes(ipad)).digest()
               + hashlib.sha512(bytes(opad)).digest())[:32]
    pad = 16 - (len(plaintext) % 16 or 16)
    padded = plaintext + bytes([pad]) * pad
    data = encrypt_cbc(derived, b"\x00" * 16, padded)

    desc = description.encode("utf-16-le") + b"\x00\x00"
    out = bytearray()
    out += struct.pack("<I", 1)
    out += _PROVIDER
    out += struct.pack("<I", 1)
    out += uuid.UUID(MK_GUID).bytes_le
    out += struct.pack("<I", 0)                          # flags
    out += struct.pack("<I", len(desc)) + desc
    out += struct.pack("<II", 0x6610, 256)               # crypt alg + keylen
    out += struct.pack("<I", len(salt)) + salt
    out += struct.pack("<I", len(hmac_key)) + hmac_key
    out += struct.pack("<II", 0x800E, 512)               # hash alg + hashlen
    out += struct.pack("<I", 16) + os.urandom(16)        # hmac2
    out += struct.pack("<I", len(data)) + data
    to_sign = bytes(out)
    sk2 = hmac.new(masterkey, hmac_key, hashlib.sha512).digest()
    sign = hmac.new(sk2, to_sign, hashlib.sha512).digest()
    out += struct.pack("<I", len(sign)) + sign
    return bytes(out)
