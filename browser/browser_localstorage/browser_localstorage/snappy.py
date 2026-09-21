"""Pure-Python Snappy raw-block decompressor (decode only).

LevelDB compresses each SSTable block with Snappy by default. The block
format (not the separate "framing format" used by the standalone snappy
CLI) is: a varint uncompressed-length preamble, then a sequence of
literal / copy elements - see
https://github.com/google/snappy/blob/main/format_description.txt.
"""

from __future__ import annotations

from browser_localstorage.varint import decode as _varint_decode


class SnappyError(ValueError):
    pass


def decompress(data: bytes) -> bytes:
    length, pos = _varint_decode(data, 0)
    out = bytearray()
    n = len(data)
    while pos < n:
        tag = data[pos]
        pos += 1
        kind = tag & 0x3
        if kind == 0:                      # literal
            lit_len = tag >> 2
            if lit_len < 60:
                lit_len += 1
            else:
                nbytes = lit_len - 59
                if pos + nbytes > n:
                    raise SnappyError("truncated literal length")
                lit_len = int.from_bytes(data[pos:pos + nbytes],
                                         "little") + 1
                pos += nbytes
            if pos + lit_len > n:
                raise SnappyError("truncated literal")
            out += data[pos:pos + lit_len]
            pos += lit_len
        else:
            if kind == 1:                  # copy, 1-byte offset
                clen = ((tag >> 2) & 0x7) + 4
                if pos >= n:
                    raise SnappyError("truncated copy tag")
                offset = ((tag >> 5) & 0x7) << 8 | data[pos]
                pos += 1
            elif kind == 2:                # copy, 2-byte offset
                clen = (tag >> 2) + 1
                if pos + 2 > n:
                    raise SnappyError("truncated copy offset")
                offset = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:                          # copy, 4-byte offset
                clen = (tag >> 2) + 1
                if pos + 4 > n:
                    raise SnappyError("truncated copy offset")
                offset = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            if offset == 0 or offset > len(out):
                raise SnappyError(f"bad copy offset {offset}")
            src = len(out) - offset
            for i in range(clen):
                out.append(out[src + i])
    if len(out) != length:
        raise SnappyError(f"decompressed length mismatch: "
                          f"expected {length}, got {len(out)}")
    return bytes(out)
