"""Parse a DPAPI master-key file and decrypt it with a supplied secret.

Layout (``%APPDATA%\\Microsoft\\Protect\\<SID>\\<GUID>``)::

    u32 version, 2xu32 unknown, 72 bytes GUID (utf-16),
    2xu32 unknown, u32 policy,
    u64 masterkey_len, u64 backupkey_len, u64 credhist_len, u64 domainkey_len,
    <masterkey blob> <backupkey blob> <credhist blob> <domainkey blob>

Each key blob::  u32 version, 16 salt, u32 rounds, u32 hashAlg, u32 cryptAlg,
                 <encrypted>

Modern (Win7+) blobs use HMAC-SHA512 PBKDF2 + AES-256-CBC.  Legacy
SHA1/3DES blobs are recognised but not decrypted in v0.1.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from analysis_dpapi.aes import decrypt_cbc

_CALG = {0x6603: "3des", 0x6610: "aes-256", 0x660E: "aes-128",
         0x660F: "aes-192", 0x6611: "aes-256"}
_HALG = {0x8004: "sha1", 0x800E: "sha512", 0x8003: "md5", 0x8009: "hmac"}


@dataclass
class KeyBlob:
    version: int
    salt: bytes
    rounds: int
    hash_alg: str
    crypt_alg: str
    ciphertext: bytes


@dataclass
class MasterKeyFile:
    guid: str
    policy: int
    masterkey: KeyBlob | None = None
    backupkey: KeyBlob | None = None
    domainkey_present: bool = False
    error: str = ""


def _parse_blob(b: bytes) -> KeyBlob:
    version, = struct.unpack_from("<I", b, 0)
    salt = b[4:20]
    rounds, halg, calg = struct.unpack_from("<III", b, 20)
    return KeyBlob(version, salt, rounds, _HALG.get(halg, hex(halg)),
                   _CALG.get(calg, hex(calg)), b[32:])


def parse_file(data: bytes) -> MasterKeyFile:
    if len(data) < 0x80:
        return MasterKeyFile("", 0, error="file too small")
    guid = data[12:12 + 72].decode("utf-16-le", "replace").rstrip("\x00")
    policy, = struct.unpack_from("<I", data, 0x5C)
    mk_len, bk_len, ch_len, dk_len = struct.unpack_from("<QQQQ", data, 0x60)
    pos = 0x80
    mkf = MasterKeyFile(guid=guid, policy=policy)
    if mk_len and pos + mk_len <= len(data):
        mkf.masterkey = _parse_blob(data[pos:pos + mk_len])
        pos += mk_len
    if bk_len and pos + bk_len <= len(data):
        mkf.backupkey = _parse_blob(data[pos:pos + bk_len])
        pos += bk_len
    pos += ch_len
    mkf.domainkey_present = bool(dk_len)
    return mkf


def _pbkdf2(prf_name, password, salt, rounds, dklen):
    return hashlib.pbkdf2_hmac(prf_name, password, salt, rounds, dklen)


def _derive_prekey(password: str | None, sid: str, *,
                   pwdhash: bytes | None = None) -> bytes:
    if pwdhash is None:
        pwdhash = hashlib.sha1(password.encode("utf-16-le")).digest()
    return hmac.new(pwdhash, (sid + "\0").encode("utf-16-le"),
                    hashlib.sha1).digest()


def decrypt_masterkey(mk: KeyBlob, sid: str, *, password: str | None = None,
                      pwdhash: bytes | None = None,
                      sha1_prekey: bytes | None = None) -> tuple[bytes, str]:
    """Return (masterkey_bytes, note). Raises ValueError on HMAC mismatch."""
    if mk.crypt_alg not in ("aes-256", "aes-128", "aes-192"):
        raise ValueError(f"unsupported cipher {mk.crypt_alg} "
                         f"(legacy 3DES/SHA1 not implemented)")
    prekey = sha1_prekey or _derive_prekey(password, sid, pwdhash=pwdhash)
    keylen = {"aes-128": 16, "aes-192": 24, "aes-256": 32}[mk.crypt_alg]
    if mk.hash_alg != "sha512":
        raise ValueError(f"unsupported hash {mk.hash_alg} "
                         f"(only Win7+ SHA512 master keys in v0.1)")
    material = _pbkdf2("sha512", prekey, mk.salt, mk.rounds, keylen + 16)
    aes_key, iv = material[:keylen], material[keylen:keylen + 16]
    cleartext = decrypt_cbc(aes_key, iv, mk.ciphertext)
    if len(cleartext) < 80 + 64:
        raise ValueError("decrypted master key too short")
    hmac_salt = cleartext[:16]
    given = cleartext[16:80]
    key = cleartext[-64:]
    outer = hmac.new(prekey, hmac_salt, hashlib.sha512).digest()
    calc = hmac.new(outer, cleartext[80:], hashlib.sha512).digest()
    if not hmac.compare_digest(calc, given):
        raise ValueError("master-key HMAC verification failed "
                         "(wrong password / SID?)")
    return key, "aes-256 / sha512"
