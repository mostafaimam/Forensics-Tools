r"""Pure-Python LZXPRESS Huffman (XPRESS Huffman) decompression - [MS-XCA] 2.2.

This is the compression used by the ``MAM\x04`` container that wraps Windows
10 / 11 Prefetch files (and by SuperFetch, WIM, DFS-R, ...).

No third-party dependencies and no OS calls: a Windows 10/11 Prefetch file
carved from a disk image can be decoded on Linux or macOS.  The algorithm and
bit-stream mechanics follow the reference decoder in Microsoft's [MS-XCA]
specification; the implementation is verified in the test-suite against the
Windows ``ntdll`` RtlDecompressBufferEx / RtlCompressBuffer round-trip.
"""

from __future__ import annotations

import io
import struct
from typing import BinaryIO

_CHUNK = 65536


class XpressError(ValueError):
    pass


def _read16(fh: BinaryIO) -> int:
    return struct.unpack("<H", fh.read(2).rjust(2, b"\x00"))[0]


class _Node:
    __slots__ = ("children", "is_leaf", "symbol")

    def __init__(self) -> None:
        self.symbol = 0
        self.is_leaf = False
        self.children: list[_Node | None] = [None, None]


def _add_leaf(nodes: list[_Node], index: int, mask: int, bits: int) -> int:
    node = nodes[0]
    i = index + 1
    while bits > 1:
        bits -= 1
        child = (mask >> bits) & 1
        if node.children[child] is None:
            node.children[child] = nodes[i]
            nodes[i].is_leaf = False
            i += 1
        node = node.children[child]
    node.children[mask & 1] = nodes[index]
    return i


def _build_tree(buf: bytes) -> _Node:
    if len(buf) != 256:
        raise XpressError("truncated Huffman code-length table")

    nodes = [_Node() for _ in range(1024)]
    symbols: list[tuple[int, int]] = []
    for i, c in enumerate(buf):
        symbols.append((c & 0x0F, i * 2))
        symbols.append((c >> 4, i * 2 + 1))
    symbols.sort()

    start = 0
    for length, _sym in symbols:
        if length > 0:
            break
        start += 1

    mask = 0
    bits = 1
    tree_index = 1
    for si in range(start, 512):
        length, sym = symbols[si]
        node = nodes[tree_index]
        node.symbol = sym
        node.is_leaf = True
        mask = (mask << (length - bits)) & 0xFFFFFFFF
        bits = length
        tree_index = _add_leaf(nodes, tree_index, mask, bits)
        mask += 1
    return nodes[0]


class _BitString:
    __slots__ = ("source", "mask", "bits")

    def __init__(self, fh: BinaryIO) -> None:
        self.source = fh
        self.mask = (_read16(fh) << 16) + _read16(fh)
        self.bits = 32

    def lookup(self, n: int) -> int:
        if n == 0:
            return 0
        return self.mask >> (32 - n)

    def skip(self, n: int) -> None:
        self.mask = (self.mask << n) & 0xFFFFFFFF
        self.bits -= n
        if self.bits < 16:
            self.mask += _read16(self.source) << (16 - self.bits)
            self.bits += 16

    def read(self, n: int) -> bytes:
        return self.source.read(n)

    def decode(self, root: _Node) -> int:
        node = root
        while not node.is_leaf:
            node = node.children[self.lookup(1)]
            self.skip(1)
            if node is None:
                raise XpressError("invalid Huffman code")
        return node.symbol


def decompress(data: bytes, expected_size: int | None = None) -> bytes:
    """Decompress an XPRESS-Huffman stream (the payload after any MAM header)."""
    src = io.BytesIO(data)
    size = len(data)
    dst = bytearray()

    def done() -> bool:
        if expected_size is not None:
            return len(dst) >= expected_size
        return src.tell() >= size

    boundary = 0
    while not done():
        table = src.read(256)
        if len(table) < 256:
            break
        root = _build_tree(table)
        bs = _BitString(src)

        # A new 256-byte Huffman table appears at every 64 KiB of *output*.
        # A match at the end of a chunk may legitimately run past the
        # boundary; we let it, then start the next chunk.
        boundary += _CHUNK
        # With the uncompressed size known we keep decoding a chunk's final
        # symbols even after the input bytes run out - the 32-bit look-ahead
        # buffer still holds them and _read16() zero-pads past EOF. A guard
        # stops a corrupt stream from looping forever.
        guard = 0
        while len(dst) < boundary and not done():
            if expected_size is None and src.tell() >= size:
                break
            if src.tell() >= size:
                guard += 1
                if guard > 48:
                    raise XpressError(
                        f"input exhausted after {len(dst)} bytes, "
                        f"expected {expected_size}"
                    )

            symbol = bs.decode(root)
            if symbol < 256:
                dst.append(symbol)
                continue

            symbol -= 256
            length = symbol & 0x0F
            offset_bits = symbol >> 4
            offset = (1 << offset_bits) + bs.lookup(offset_bits)

            if length == 15:
                length = src.read(1)[0] if src.tell() < size else 0
                length += 15
                if length == 270:
                    length = _read16(src)
            bs.skip(offset_bits)
            length += 3

            if offset > len(dst):
                raise XpressError(
                    f"match offset {offset} before start of output"
                )
            remaining = length
            while remaining > 0:
                take = min(remaining, offset)
                dst += dst[-offset:(-offset + take) or None]
                remaining -= take

    if expected_size is not None:
        if len(dst) < expected_size:
            raise XpressError(
                f"decompressed {len(dst)} bytes, expected {expected_size}"
            )
        return bytes(dst[:expected_size])
    return bytes(dst)
