"""Parse and decrypt a DPAPI data blob given the right master key."""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from analysis_dpapi.aes import decrypt_cbc

_CALG = {0x6603: ("3des", 24, 8), 0x6610: ("aes-256", 32, 16),
         0x6611: ("aes-256", 32, 16), 0x660E: ("aes-128", 16, 16),
         0x660F: ("aes-192", 24, 16)}
_HALG = {0x8004: ("sha1", hashlib.sha1, 64),
         0x800E: ("sha512", hashlib.sha512, 128),
         0x8003: ("md5", hashlib.md5, 64)}


@dataclass
class DpapiBlob:
    version: int
    provider_guid: str
    mk_guid: str
    flags: int
    description: str
    crypt_alg: str
    hash_alg: str
    salt: bytes
    hmac_key: bytes
    sign: bytes
    data: bytes
    to_sign: bytes


def _pull(buf, off):
    n, = struct.unpack_from("<I", buf, off)
    return buf[off + 4:off + 4 + n], off + 4 + n


def parse_blob(buf: bytes, base: int = 0) -> tuple[DpapiBlob, int]:
    o = base
    version, = struct.unpack_from("<I", buf, o)
    o += 4
    provider = buf[o:o + 16]
    o += 16
    _mkver, = struct.unpack_from("<I", buf, o)
    o += 4
    mkguid = buf[o:o + 16]
    o += 16
    flags, = struct.unpack_from("<I", buf, o)
    o += 4
    desc, o = _pull(buf, o)
    calg, = struct.unpack_from("<I", buf, o)
    o += 4
    _calg_len, = struct.unpack_from("<I", buf, o)
    o += 4
    salt, o = _pull(buf, o)
    hmac_key, o = _pull(buf, o)
    halg, = struct.unpack_from("<I", buf, o)
    o += 4
    _halg_len, = struct.unpack_from("<I", buf, o)
    o += 4
    hmac2, o = _pull(buf, o)
    data, o = _pull(buf, o)
    sign_start = o
    sign, o = _pull(buf, o)

    import uuid
    b = DpapiBlob(
        version=version, provider_guid=str(uuid.UUID(bytes_le=provider)),
        mk_guid=str(uuid.UUID(bytes_le=mkguid)), flags=flags,
        description=desc.decode("utf-16-le", "replace").rstrip("\x00"),
        crypt_alg=_CALG.get(calg, (hex(calg), 0, 0))[0],
        hash_alg=_HALG.get(halg, (hex(halg), None, 0))[0],
        salt=salt, hmac_key=hmac_key, sign=sign, data=data,
        to_sign=buf[base:sign_start])
    b._calg = calg  # type: ignore[attr-defined]
    b._halg = halg  # type: ignore[attr-defined]
    return b, o


@dataclass
class Decrypted:
    plaintext: bytes
    description: str
    mk_guid: str
    signature_verified: bool
    note: str = ""


def _derive_key(session_key: bytes, hmod, block: int, keylen: int) -> bytes:
    ipad = bytearray(b"\x36" * block)
    opad = bytearray(b"\x5c" * block)
    for i, b in enumerate(session_key):
        ipad[i] ^= b
        opad[i] ^= b
    return (hmod(bytes(ipad)).digest() + hmod(bytes(opad)).digest())[:keylen]


def _unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def decrypt_blob(b: DpapiBlob, masterkey: bytes, *,
                 entropy: bytes | None = None) -> Decrypted:
    calg = getattr(b, "_calg")
    halg = getattr(b, "_halg")
    if calg not in _CALG or _CALG[calg][0] == "3des":
        raise ValueError(f"unsupported cipher {b.crypt_alg}")
    if halg not in _HALG or _HALG[halg][1] is None:
        raise ValueError(f"unsupported hash {b.hash_alg}")
    _n, keylen, ivlen = _CALG[calg]
    _hn, hmod, block = _HALG[halg]

    mac = hmac.new(masterkey, b.salt, hmod)
    if entropy:
        mac.update(entropy)
    session_key = mac.digest()

    if len(session_key) > block:
        derived = hmac.new(session_key, b"", hmod).digest()[:keylen]
    else:
        derived = _derive_key(session_key, hmod, block, keylen)
    key = derived[:keylen]
    plain = _unpad(decrypt_cbc(key, b"\x00" * ivlen, b.data))

    verified = False
    try:
        sk2 = hmac.new(masterkey, b.hmac_key, hmod).digest()
        calc = hmac.new(sk2, b.to_sign, hmod).digest()
        verified = hmac.compare_digest(calc, b.sign)
    except Exception:  # noqa: BLE001
        verified = False

    return Decrypted(plaintext=plain, description=b.description,
                     mk_guid=b.mk_guid, signature_verified=verified,
                     note="" if verified else "signature not verified")
