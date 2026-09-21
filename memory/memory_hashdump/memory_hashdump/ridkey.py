"""Derive the two classic RID-keyed DES keys used by the legacy SAM
hash-obfuscation scheme (the "sid_to_key" / "StrToKey" transform every
public SAM-dump tool implements identically)."""

from __future__ import annotations

import struct


def _set_odd_parity(b: int) -> int:
    if bin(b).count("1") % 2 == 0:
        return b ^ 1
    return b


def _expand_7_to_8(key7: bytes) -> bytes:
    out = bytearray(8)
    out[0] = key7[0] >> 1
    out[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
    out[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
    out[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
    out[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
    out[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
    out[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
    out[7] = key7[6] & 0x7F
    return bytes(_set_odd_parity((b << 1) & 0xFE) for b in out)


def deskeys_from_rid(rid: int) -> tuple[bytes, bytes]:
    s = struct.pack("<I", rid)
    key1 = bytes([s[0], s[1], s[2], s[3], s[0], s[1], s[2]])
    key2 = bytes([s[3], s[0], s[1], s[2], s[3], s[0], s[1]])
    return _expand_7_to_8(key1), _expand_7_to_8(key2)
