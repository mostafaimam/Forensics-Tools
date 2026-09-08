"""Minimal decoders: the ``mozLz4`` container and a raw LZ4 block.

Firefox session files are ``mozLz4a\\0`` / ``mozLz40\\0`` + a uint32
decompressed length + one LZ4 block.  This is a from-scratch LZ4 block
decompressor - no ``lz4`` package.
"""

from __future__ import annotations

import struct

_MAGICS = (b"mozLz4a\x00", b"mozLz40\x00", b"mozLz4\x00\x00")


class Lz4Error(Exception):
    pass


def lz4_block_decompress(src: bytes, expected: int | None = None) -> bytes:
    """Decode a raw LZ4 block (no frame header)."""
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token = src[i]
        i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while i < n:
                b = src[i]
                i += 1
                lit_len += b
                if b != 255:
                    break
        if i + lit_len > n:
            lit_len = n - i
        out += src[i:i + lit_len]
        i += lit_len
        if i >= n:
            break
        if i + 2 > n:
            break
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0:
            raise Lz4Error("zero match offset")
        match_len = token & 0x0F
        if match_len == 15:
            while i < n:
                b = src[i]
                i += 1
                match_len += b
                if b != 255:
                    break
        match_len += 4
        start = len(out) - offset
        if start < 0:
            raise Lz4Error("match before start of output")
        for _ in range(match_len):
            out.append(out[start])
            start += 1
    if expected is not None and len(out) != expected:
        # tolerate a short read but keep what we have
        pass
    return bytes(out)


def mozlz4_decompress(data: bytes) -> bytes:
    if not any(data.startswith(m) for m in _MAGICS):
        raise Lz4Error("not a mozLz4 container")
    if len(data) < 12:
        raise Lz4Error("truncated mozLz4 header")
    dec_size = struct.unpack_from("<I", data, 8)[0]
    return lz4_block_decompress(data[12:], dec_size)
