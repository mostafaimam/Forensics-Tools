"""Decrypt SAM LM/NT hashes given the SYSTEM hive's boot key.

Two schemes exist, selected by the revision field at the start of
``SAM\\Domains\\Account\\F``:

- **Revision 2 (legacy, pre-Vista RC4 scheme).** The "classic" pwdump
  -era algorithm: MD5(F-salt + a fixed constant string + bootkey +
  another fixed constant) is an RC4 key that decrypts a "hashed boot
  key"; each user's stored hash is then RC4-decrypted with a key mixing
  that hashed boot key with the account's RID, and the RC4 output is
  finally run through two rounds of DES keyed from the RID itself. This
  exact algorithm has been implemented identically by every public
  SAM-dump tool for two decades - high confidence.
- **Revision 3 (modern, AES scheme).** AES-CBC replaces the RC4 +
  RID-DES layers: the F value's own salt/ciphertext yields the hashed
  boot key directly via one AES-CBC decrypt, and each user's hash is a
  second AES-CBC decrypt keyed by that hashed boot key with a per-hash
  salt. The overall shape is well established, but the exact byte
  offsets of the AES sub-structure within F and V are this project's
  best-effort reading of community SAM-parsing references, not a
  published Microsoft specification - see the README before relying on
  revision-3 output with the same confidence as revision-2.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from memory_hashdump import aes, des, rc4
from memory_hashdump.ridkey import deskeys_from_rid

_AQWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
_ANUM = b"0123456789012345678901234567890123456789\x00"
_LMPASSWORD = b"LMPASSWORD\x00"
_NTPASSWORD = b"NTPASSWORD\x00"

_EMPTY_LM = bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")
_EMPTY_NT = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")


class SamHashError(ValueError):
    pass


@dataclass
class HashedBootKey:
    key: bytes
    revision: int


def compute_hashed_boot_key(f_value: bytes, bootkey: bytes) -> HashedBootKey:
    if len(f_value) < 4:
        raise SamHashError("SAM F value is too short")
    revision = struct.unpack_from("<L", f_value, 0)[0]
    if revision == 2:
        if len(f_value) < 0x90:
            raise SamHashError("SAM F value too short for the legacy "
                              "(revision 2) layout")
        salt = f_value[0x70:0x80]
        encrypted = f_value[0x80:0x90]
        rc4_key = hashlib.md5(salt + _AQWERTY + bootkey + _ANUM).digest()
        return HashedBootKey(rc4.crypt(rc4_key, encrypted)[:16], 2)
    if revision == 3:
        if len(f_value) < 0x7C + 16:
            raise SamHashError("SAM F value too short for the AES "
                              "(revision 3) layout")
        data_len = struct.unpack_from("<L", f_value, 0x68)[0] or 32
        data_len = min(max(data_len, 16), 64)
        data_len -= data_len % 16
        salt = f_value[0x6C:0x7C]
        encrypted = f_value[0x7C:0x7C + data_len]
        if len(encrypted) < 16:
            raise SamHashError("SAM F value truncated in the AES key data")
        plain = aes.decrypt_cbc(bootkey, salt, encrypted)
        return HashedBootKey(plain[:16], 3)
    raise SamHashError(f"unsupported SAM F revision {revision} "
                      f"(v0.1 supports 2 and 3)")


def _rc4_hash_key(hbk: bytes, rid: int, const: bytes) -> bytes:
    return hashlib.md5(hbk + struct.pack("<L", rid) + const).digest()


def decrypt_hash_legacy(encrypted16: bytes, rid: int, hbk: bytes,
                        *, is_nt: bool) -> bytes:
    const = _NTPASSWORD if is_nt else _LMPASSWORD
    rc4_key = _rc4_hash_key(hbk, rid, const)
    obfuscated = rc4.crypt(rc4_key, encrypted16)
    k1, k2 = deskeys_from_rid(rid)
    return des.decrypt_block(k1, obfuscated[:8]) + \
        des.decrypt_block(k2, obfuscated[8:16])


def decrypt_hash_aes(encrypted: bytes, salt: bytes, hbk: bytes) -> bytes:
    n = len(encrypted) - (len(encrypted) % 16)
    return aes.decrypt_cbc(hbk[:16], salt, encrypted[:n])[:16]


@dataclass
class HashBlob:
    pekid: int
    revision: int
    salt: bytes | None
    encrypted: bytes


def _parse_hash_blob(raw: bytes) -> HashBlob | None:
    if len(raw) < 4:
        return None
    pekid, revision = struct.unpack_from("<HH", raw, 0)
    if revision == 1:
        return HashBlob(pekid, revision, None, raw[4:20])
    if revision in (2, 3):
        if len(raw) < 4 + 16 + 16:
            return None
        return HashBlob(pekid, revision, raw[4:20], raw[20:36])
    return None


_LM_HEADER_OFFSET = 0x9C
_NT_HEADER_OFFSET = 0xA8
_DATA_BASE = 0xCC


def _extract_field(v_value: bytes, header_offset: int) -> bytes:
    if header_offset + 12 > len(v_value):
        return b""
    rel_offset, length, _unk = struct.unpack_from("<III", v_value,
                                                   header_offset)
    start = _DATA_BASE + rel_offset
    end = start + length
    if length == 0 or start < 0 or end > len(v_value):
        return b""
    return v_value[start:end]


def decode_user_hashes(v_value: bytes, rid: int, hbk: HashedBootKey
                       ) -> tuple[bytes | None, bytes | None]:
    """Return (lm_hash, nt_hash), either ``None`` if absent/undecodable."""
    lm_raw = _extract_field(v_value, _LM_HEADER_OFFSET)
    nt_raw = _extract_field(v_value, _NT_HEADER_OFFSET)
    lm = _decode_one(lm_raw, rid, hbk, is_nt=False)
    nt = _decode_one(nt_raw, rid, hbk, is_nt=True)
    return lm, nt


def _decode_one(raw: bytes, rid: int, hbk: HashedBootKey, *, is_nt: bool
               ) -> bytes | None:
    blob = _parse_hash_blob(raw)
    if blob is None:
        return None
    if blob.revision == 1:
        return decrypt_hash_legacy(blob.encrypted, rid, hbk.key, is_nt=is_nt)
    return decrypt_hash_aes(blob.encrypted, blob.salt, hbk.key)


def hash_hex(h: bytes | None) -> str:
    return h.hex() if h else ""


def is_empty_hash(h: bytes | None, *, is_nt: bool) -> bool:
    if h is None:
        return False
    return h == (_EMPTY_NT if is_nt else _EMPTY_LM)
