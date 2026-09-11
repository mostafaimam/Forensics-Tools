"""Minimal pure-Python AES (decrypt: ECB + CBC). Standard reference tables."""

from __future__ import annotations

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_INV_SBOX = bytes(_INV_SBOX)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D)


def _xt(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xt(a)
        b >>= 1
    return p & 0xFF


def _expand_key(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w


def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[rnd * 4 + c][r]


def _inv_sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c] = _INV_SBOX[s[r][c]]


def _inv_shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]


def _inv_mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
        s[1][c] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
        s[2][c] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
        s[3][c] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)


def _sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c] = _SBOX[s[r][c]]


def _shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]


def _mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        s[3][c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _encrypt_block(block: bytes, w, nr: int) -> bytes:
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, 0)
    for rnd in range(1, nr):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, w, rnd)
    _sub_bytes(s)
    _shift_rows(s)
    _add_round_key(s, w, nr)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def encrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _encrypt_block(blk, w, nr)
        out += enc
        prev = enc
    return bytes(out)


def _decrypt_block(block: bytes, w, nr: int) -> bytes:
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(s)
        _inv_sub_bytes(s)
        _add_round_key(s, w, rnd)
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_round_key(s, w, 0)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def decrypt_ecb(key: bytes, data: bytes) -> bytes:
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    return b"".join(_decrypt_block(data[i:i + 16], w, nr)
                    for i in range(0, len(data), 16))


def decrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _decrypt_block(blk, w, nr)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def encrypt_ecb(key: bytes, data: bytes) -> bytes:
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    return b"".join(_encrypt_block(data[i:i + 16], w, nr)
                    for i in range(0, len(data), 16))


def ctr_xor(key: bytes, iv16: bytes, data: bytes) -> bytes:
    """AES-CTR keystream XOR (encrypt == decrypt). `iv16` is the initial
    128-bit counter block; incremented as a big-endian integer per block,
    matching the CCM counter-mode convention."""
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    ctr = int.from_bytes(iv16, "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        block = ctr.to_bytes(16, "big")
        ks = _encrypt_block(block, w, nr)
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return bytes(out)


def cbc_mac(key: bytes, data: bytes) -> bytes:
    """CBC-MAC over `data` (must be a multiple of 16 bytes), IV zero."""
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    prev = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _encrypt_block(blk, w, nr)
    return prev


def _xts_tweaks(key2: bytes, sector_index: int, nblocks: int) -> list:
    w2 = _expand_key(key2)
    nr2 = len(key2) // 4 + 6
    tweak_pt = sector_index.to_bytes(16, "little")
    t = list(_encrypt_block(tweak_pt, w2, nr2))
    out = []
    for _ in range(nblocks):
        out.append(bytes(t))
        carry = 0
        for j in range(16):
            new_carry = t[j] >> 7
            t[j] = ((t[j] << 1) | carry) & 0xFF
            carry = new_carry
        if carry:
            t[0] ^= 0x87
    return out


def xts_decrypt_sector(key1: bytes, key2: bytes, sector_index: int,
                       data: bytes) -> bytes:
    """AES-XTS decrypt one sector (IEEE P1619). `sector_index` is the
    128-bit tweak value (little-endian per the standard)."""
    w1 = _expand_key(key1)
    nr1 = len(key1) // 4 + 6
    out = bytearray()
    for i, t in zip(range(0, len(data), 16),
                    _xts_tweaks(key2, sector_index, len(data) // 16)):
        blk = data[i:i + 16]
        x = bytes(b ^ tt for b, tt in zip(blk, t))
        p = _decrypt_block(x, w1, nr1)
        out += bytes(b ^ tt for b, tt in zip(p, t))
    return bytes(out)


def xts_encrypt_sector(key1: bytes, key2: bytes, sector_index: int,
                       data: bytes) -> bytes:
    w1 = _expand_key(key1)
    nr1 = len(key1) // 4 + 6
    out = bytearray()
    for i, t in zip(range(0, len(data), 16),
                    _xts_tweaks(key2, sector_index, len(data) // 16)):
        blk = data[i:i + 16]
        x = bytes(b ^ tt for b, tt in zip(blk, t))
        c = _encrypt_block(x, w1, nr1)
        out += bytes(b ^ tt for b, tt in zip(c, t))
    return bytes(out)
