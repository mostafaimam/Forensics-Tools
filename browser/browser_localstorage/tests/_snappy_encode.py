"""A minimal literal-only Snappy encoder, for testing the decompressor.

Valid (if inefficient) Snappy: no copy elements, just literal runs.
"""

from __future__ import annotations

import struct

from browser_localstorage.varint import encode as v


def compress_literal_only(data: bytes) -> bytes:
    out = bytearray()
    out += v(len(data))
    pos = 0
    n = len(data)
    while pos < n:
        clen = min(n - pos, 65536)
        chunk = data[pos:pos + clen]
        if clen <= 60:
            out.append(((clen - 1) << 2) | 0)
        else:
            out.append((63 << 2) | 0)
            out += struct.pack("<I", clen - 1)
        out += chunk
        pos += clen
    return bytes(out)
