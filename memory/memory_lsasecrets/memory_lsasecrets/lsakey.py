"""Decrypt the shared "LSA_SECRET" AES-CBC blob format.

The same wrapper shape is used for two different things: decrypting
``SECURITY\\Policy\\PolEKList`` with the SYSTEM boot key yields the
LSA encryption key; decrypting a ``SECURITY\\Policy\\Secrets\\<name>\\
CurrVal`` value with *that* LSA key yields the actual secret. Both
share one on-disk shape (well established across public SAM/LSA
tooling):

    offset  size  field
    0       4     version (expected 1)
    4       16    key GUID (unused here)
    20      4     encryption algorithm id (unused here)
    24      4     flags (unused here)
    28      16    AES-CBC salt / IV
    44      ...   AES-CBC ciphertext

Decrypting the ciphertext yields an inner ``LSA_SECRET_BLOB``:

    offset  size  field
    0       4     secret length
    4       12    unknown / padding
    16      N     the secret bytes (N = the length field above)

Extracting the actual AES key material *out of* the decrypted
``PolEKList`` payload (as opposed to this shared wrapper, which is high
confidence) is this project's best-effort reading of community
references - see the README before relying on it as heavily as the
wrapper format itself.
"""

from __future__ import annotations

from memory_lsasecrets import aes

_WRAPPER_HEADER = 44
_INNER_HEADER = 16
_POLEKLIST_KEY_OFFSET = 36
_POLEKLIST_KEY_LEN = 32


class LsaSecretError(ValueError):
    pass


def _decrypt_wrapper(key: bytes, raw: bytes) -> bytes:
    if len(raw) < _WRAPPER_HEADER + 16:
        raise LsaSecretError("LSA secret blob is too short")
    salt = raw[28:44]
    ciphertext = raw[44:]
    n = len(ciphertext) - (len(ciphertext) % 16)
    if n < 16:
        raise LsaSecretError("LSA secret ciphertext is too short")
    plain = aes.decrypt_cbc(key[:16], salt, ciphertext[:n])
    if len(plain) < _INNER_HEADER:
        raise LsaSecretError("decrypted LSA secret is too short")
    length = int.from_bytes(plain[0:4], "little")
    secret = plain[_INNER_HEADER:_INNER_HEADER + length]
    if len(secret) != length:
        raise LsaSecretError("decrypted LSA secret length does not match "
                            "its own header - wrong key")
    return secret


def derive_lsa_key(bootkey: bytes, polek_list: bytes) -> bytes:
    payload = _decrypt_wrapper(bootkey, polek_list)
    if len(payload) < _POLEKLIST_KEY_OFFSET + _POLEKLIST_KEY_LEN:
        raise LsaSecretError("PolEKList payload too short for the "
                            "expected key material offset")
    return payload[_POLEKLIST_KEY_OFFSET:
                   _POLEKLIST_KEY_OFFSET + _POLEKLIST_KEY_LEN]


def decrypt_secret(lsa_key: bytes, curr_val: bytes) -> bytes:
    return _decrypt_wrapper(lsa_key, curr_val)
