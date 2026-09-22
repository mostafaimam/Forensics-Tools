"""LZ4 block decompression (no frame header) - a public, exact spec.

Unlike the tracev3-specific framing elsewhere in this package, this is
straightforward: token byte (literal-length nibble, match-length
nibble) with the standard byte-run length extension, a literal run, a
2-byte little-endian match offset, and a match copy (which may
overlap the not-yet-written output, as LZ4 requires byte-by-byte).
"""

from __future__ import annotations


class Lz4Error(ValueError):
    pass


def _read_length(data: bytes, pos: int, base: int) -> tuple[int, int]:
    length = base
    if base == 0x0F:
        while True:
            if pos >= len(data):
                raise Lz4Error("truncated length byte-run")
            b = data[pos]
            pos += 1
            length += b
            if b != 0xFF:
                break
    return length, pos


def decompress_block(data: bytes, *, max_output: int = 64 << 20) -> bytes:
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n:
        token = data[pos]
        pos += 1
        literal_len, pos = _read_length(data, pos, token >> 4)
        if pos + literal_len > n:
            raise Lz4Error("literal run runs past end of input")
        out += data[pos:pos + literal_len]
        pos += literal_len
        if pos >= n:
            break  # a block may legally end after a final literal run
        if pos + 2 > n:
            raise Lz4Error("truncated match offset")
        offset = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if offset == 0 or offset > len(out):
            raise Lz4Error(f"match offset {offset} invalid at output "
                          f"length {len(out)}")
        match_len, pos = _read_length(data, pos, token & 0x0F)
        match_len += 4
        start = len(out) - offset
        for i in range(match_len):
            out.append(out[start + i])
        if len(out) > max_output:
            raise Lz4Error("decompressed output exceeds max_output limit")
    return bytes(out)
