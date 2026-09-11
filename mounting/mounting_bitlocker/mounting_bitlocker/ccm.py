"""AES-CCM (NIST SP 800-38C) decrypt + verify, built on the bundled AES."""

from __future__ import annotations

import hmac
import struct

from mounting_bitlocker import aes as _aes


class CcmError(ValueError):
    pass


def _b0(flags: int, nonce: bytes, msg_len: int, length_field: int) -> bytes:
    return bytes([flags]) + nonce + msg_len.to_bytes(length_field, "big")


def _ctr_block(ctr_flags: int, nonce: bytes, counter: int,
              length_field: int) -> bytes:
    return bytes([ctr_flags]) + nonce + counter.to_bytes(length_field, "big")


def decrypt_and_verify(key: bytes, nonce: bytes, blob: bytes, *,
                       aad: bytes = b"", mac_len: int = 16) -> bytes:
    """`blob` is ciphertext with the `mac_len`-byte tag appended (BitLocker's
    on-disk layout). Raises CcmError if the tag does not verify."""
    if len(blob) < mac_len:
        raise CcmError("ciphertext shorter than the MAC")
    ct, tag = blob[:-mac_len], blob[-mac_len:]
    length_field = 15 - len(nonce)
    if not (2 <= length_field <= 8):
        raise CcmError(f"unsupported nonce length {len(nonce)}")

    ctr_flags = (((mac_len - 2) // 2) << 3) | (length_field - 1)
    a0 = _ctr_block(ctr_flags, nonce, 0, length_field)
    a1 = _ctr_block(ctr_flags, nonce, 1, length_field)

    plaintext = _aes.ctr_xor(key, a1, ct)

    flags = ctr_flags | (0x40 if aad else 0)
    mac_input = bytearray(_b0(flags, nonce, len(ct), length_field))
    if aad:
        if len(aad) >= 0xFF00:
            raise CcmError("AAD too long for this implementation")
        enc = struct.pack(">H", len(aad)) + aad
        enc += b"\x00" * ((-len(enc)) % 16)
        mac_input += enc
    mac_input += plaintext
    mac_input += b"\x00" * ((-len(plaintext)) % 16)

    raw_tag = _aes.cbc_mac(key, bytes(mac_input))[:mac_len]
    s0 = _aes.encrypt_ecb(key, a0)
    computed = bytes(a ^ b for a, b in zip(raw_tag, s0[:mac_len]))
    if not hmac.compare_digest(computed, tag):
        raise CcmError("CCM tag verification failed (wrong key?)")
    return plaintext


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, *,
           aad: bytes = b"", mac_len: int = 16) -> bytes:
    """The encrypt side, used only to build test fixtures."""
    length_field = 15 - len(nonce)
    ctr_flags = (((mac_len - 2) // 2) << 3) | (length_field - 1)
    a0 = _ctr_block(ctr_flags, nonce, 0, length_field)
    a1 = _ctr_block(ctr_flags, nonce, 1, length_field)

    flags = ctr_flags | (0x40 if aad else 0)
    mac_input = bytearray(_b0(flags, nonce, len(plaintext), length_field))
    if aad:
        enc = struct.pack(">H", len(aad)) + aad
        enc += b"\x00" * ((-len(enc)) % 16)
        mac_input += enc
    mac_input += plaintext
    mac_input += b"\x00" * ((-len(plaintext)) % 16)

    raw_tag = _aes.cbc_mac(key, bytes(mac_input))[:mac_len]
    s0 = _aes.encrypt_ecb(key, a0)
    tag = bytes(a ^ b for a, b in zip(raw_tag, s0[:mac_len]))
    ct = _aes.ctr_xor(key, a1, plaintext)
    return ct + tag
