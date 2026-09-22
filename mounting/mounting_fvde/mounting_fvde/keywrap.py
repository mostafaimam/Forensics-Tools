"""RFC 3394 AES Key Wrap/Unwrap.

This is NIST/IETF standard, published crypto (SP 800-38F / RFC 3394) -
unlike the CoreStorage plist layout in ``corestorage.py``, there is
nothing reverse-engineered or uncertain about this file.
"""

from __future__ import annotations

from mounting_fvde.aes import decrypt_ecb, encrypt_ecb

_IV = bytes.fromhex("A6A6A6A6A6A6A6A6")


class KeyWrapError(ValueError):
    pass


def unwrap(kek: bytes, wrapped: bytes) -> bytes:
    if len(wrapped) % 8 or len(wrapped) < 24:
        raise KeyWrapError("wrapped key length must be a multiple of 8, "
                          "at least 24 bytes")
    n = len(wrapped) // 8 - 1
    a = wrapped[:8]
    r = [wrapped[8 + 8 * i: 16 + 8 * i] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = (n * j + i).to_bytes(8, "big")
            a_int = int.from_bytes(a, "big") ^ int.from_bytes(t, "big")
            block = a_int.to_bytes(8, "big") + r[i - 1]
            dec = decrypt_ecb(kek, block)
            a = dec[:8]
            r[i - 1] = dec[8:]
    if a != _IV:
        raise KeyWrapError("integrity check failed - wrong key-encryption "
                          "key or corrupt wrapped data")
    return b"".join(r)


def wrap(kek: bytes, plaintext_key: bytes) -> bytes:
    if len(plaintext_key) % 8:
        raise KeyWrapError("plaintext key length must be a multiple of 8")
    n = len(plaintext_key) // 8
    a = _IV
    r = [plaintext_key[8 * i:8 * i + 8] for i in range(n)]
    for j in range(6):
        for i in range(1, n + 1):
            block = a + r[i - 1]
            enc = encrypt_ecb(kek, block)
            t = (n * j + i).to_bytes(8, "big")
            a = (int.from_bytes(enc[:8], "big") ^
                int.from_bytes(t, "big")).to_bytes(8, "big")
            r[i - 1] = enc[8:]
    return a + b"".join(r)
