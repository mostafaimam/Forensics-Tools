"""Derive a CoreStorage volume key and decrypt with it.

The crypto here (PBKDF2, RFC 3394 unwrap, AES-XTS) is exact and
standard. Salt / iteration count / wrapped-key bytes are supplied by
the caller rather than auto-parsed - see the package docstring.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from mounting_fvde import aes
from mounting_fvde.keywrap import KeyWrapError, unwrap

_HFS_OFFSET = 1024
_HFS_MAGICS = (b"H+", b"HX")


class UnlockError(ValueError):
    pass


@dataclass
class UnlockResult:
    vek: bytes
    key1: bytes
    key2: bytes


def derive_vek(password: str, salt: bytes, iterations: int,
               wrapped: bytes, *, dklen: int = 16) -> bytes:
    kek = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                              iterations, dklen=dklen)
    try:
        vek = unwrap(kek, wrapped)
    except KeyWrapError as e:
        raise UnlockError(f"key unwrap failed (wrong password, salt, "
                          f"iteration count, or wrapped-key bytes): {e}")
    return vek


def xts_keys_from_vek(vek: bytes) -> tuple[bytes, bytes]:
    """Split a VEK into the two AES-XTS-128 keys via the standard IEEE
    P1619 convention (first half = data key, second half = tweak key) -
    the well-established way a doubled-length XTS key is split."""
    if len(vek) not in (32,):
        raise UnlockError(f"expected a 32-byte VEK for AES-XTS-128, got "
                          f"{len(vek)} bytes")
    return vek[:16], vek[16:]


def decrypt_and_verify(key1: bytes, key2: bytes, data: bytes,
                       sector_index: int = 0) -> bytes:
    plaintext = aes.xts_decrypt_sector(key1, key2, sector_index, data)
    if len(plaintext) >= _HFS_OFFSET + 2:
        magic = plaintext[_HFS_OFFSET:_HFS_OFFSET + 2]
        if magic in _HFS_MAGICS:
            return plaintext
        raise UnlockError(
            f"decrypted, but no HFS+/HFSX volume-header magic found at "
            f"offset {_HFS_OFFSET} (got {magic!r}) - the derived key is "
            f"probably wrong")
    return plaintext
