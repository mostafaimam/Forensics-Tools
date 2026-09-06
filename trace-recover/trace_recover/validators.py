"""Structural validators.

Each validator is called with a ``memoryview`` that starts at a candidate
header and extends to at most ``max_size`` bytes (or end of source).  It
returns:

* ``int``   - the exact byte length of a valid object starting at offset 0
* ``None``  - not valid / cannot determine a length here

A validator that can only partially confirm may still return a length; the
scanner records the confidence separately (footer-terminated vs
structure-sized vs max-size-truncated).
"""

from __future__ import annotations

import struct

_U16BE = ">H"
_U32BE = ">I"
_U32LE = "<I"


def v_bmp(buf: memoryview) -> int | None:
    if len(buf) < 6 or buf[:2] != b"BM":
        return None
    (size,) = struct.unpack_from(_U32LE, buf, 2)
    if 26 <= size <= len(buf):
        return size
    return None


def v_sqlite(buf: memoryview) -> int | None:
    if len(buf) < 100 or bytes(buf[:16]) != b"SQLite format 3\x00":
        return None
    (page_size,) = struct.unpack_from(_U16BE, buf, 16)
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size & (page_size - 1):
        return None
    (page_count,) = struct.unpack_from(_U32BE, buf, 28)
    if not (1 <= page_count <= 1 << 32):
        return None
    total = page_size * page_count
    if 512 <= total <= len(buf):
        return total
    return None


def v_png(buf: memoryview) -> int | None:
    sig = b"\x89PNG\r\n\x1a\n"
    if len(buf) < 8 or buf[:8] != sig:
        return None
    off = 8
    n = len(buf)
    while off + 8 <= n:
        (clen,) = struct.unpack_from(_U32BE, buf, off)
        ctype = bytes(buf[off + 4:off + 8])
        off += 12 + clen  # length + type + data + crc
        if ctype == b"IEND":
            return off if off <= n else None
        if clen > n:
            return None
    return None


def v_gif(buf: memoryview) -> int | None:
    b = bytes(buf)
    if len(b) < 14 or b[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    p = 6
    flags = b[10]
    p = 13
    if flags & 0x80:                             # global colour table
        p += 3 * (2 ** ((flags & 0x07) + 1))
    n = len(b)
    while p < n:
        blk = b[p]
        p += 1
        if blk == 0x3B:                          # trailer
            return p
        if blk == 0x21:                          # extension
            p += 1                               # label
            p = _skip_subblocks(b, p)
        elif blk == 0x2C:                        # image descriptor
            if p + 9 > n:
                return None
            lflags = b[p + 8]
            p += 9
            if lflags & 0x80:
                p += 3 * (2 ** ((lflags & 0x07) + 1))
            p += 1                               # LZW minimum code size
            p = _skip_subblocks(b, p)
        else:
            return None
        if p is None:
            return None
    return None


def _skip_subblocks(b: bytes, p: int):
    n = len(b)
    while p < n:
        size = b[p]
        p += 1
        if size == 0:
            return p
        p += size
    return None


def v_jpeg(buf: memoryview) -> int | None:
    b = bytes(buf)
    if len(b) < 4 or b[:2] != b"\xff\xd8":
        return None
    p = 2
    n = len(b)
    while p + 1 < n:
        if b[p] != 0xFF:
            return None
        while p < n and b[p] == 0xFF:
            p += 1
        if p >= n:
            return None
        marker = b[p]
        p += 1
        if marker == 0xD9:                       # EOI
            return p
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:
            continue
        if p + 2 > n:
            return None
        seg_len = (b[p] << 8) | b[p + 1]
        if seg_len < 2:
            return None
        if marker == 0xDA:                       # start of scan
            p += seg_len
            while p + 1 < n:
                if b[p] == 0xFF and b[p + 1] != 0x00 and \
                        not (0xD0 <= b[p + 1] <= 0xD7):
                    break
                p += 1
            continue
        p += seg_len
    return None


def v_pdf(buf: memoryview) -> int | None:
    if buf[:5] != b"%PDF-":
        return None
    b = bytes(buf)
    end = b.rfind(b"%%EOF")
    if end < 0:
        return None
    end += 5
    while end < len(b) and b[end] in (0x0d, 0x0a):
        end += 1
    return end


def v_zip(buf: memoryview) -> int | None:
    """Locate the End Of Central Directory record and size the archive."""
    if buf[:4] != b"PK\x03\x04":
        return None
    b = bytes(buf)
    eocd = b.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(b):
        return None
    comment_len = struct.unpack_from("<H", b, eocd + 20)[0]
    total = eocd + 22 + comment_len
    return total if total <= len(b) else eocd + 22


def v_gzip(buf: memoryview) -> int | None:
    if len(buf) < 18 or buf[:3] != b"\x1f\x8b\x08":
        return None
    try:
        import zlib

        d = zlib.decompressobj(31)
        consumed = 0
        for i in range(0, len(buf), 65536):
            chunk = bytes(buf[i:i + 65536])
            d.decompress(chunk)
            consumed = i + len(chunk) - len(d.unused_data)
            if d.eof:
                return consumed
        return None
    except Exception:
        return None


def v_evtx(buf: memoryview) -> int | None:
    if len(buf) < 4096 or bytes(buf[:8]) != b"ElfFile\x00":
        return None
    (num_chunks,) = struct.unpack_from("<H", buf, 0x1a)
    if not (0 < num_chunks < 100000):
        return None
    total = 4096 + num_chunks * 65536
    return total if total <= len(buf) else None


def v_regf(buf: memoryview) -> int | None:
    if len(buf) < 0x200 or buf[:4] != b"regf":
        return None
    # hive bins size at 0x28 (u32), header is 0x1000
    (hbins_size,) = struct.unpack_from(_U32LE, buf, 0x28)
    total = 0x1000 + hbins_size
    if 0x1000 < total <= len(buf):
        return total
    return None


VALIDATORS = {
    "bmp": v_bmp,
    "sqlite": v_sqlite,
    "png": v_png,
    "gif": v_gif,
    "jpg": v_jpeg,
    "pdf": v_pdf,
    "zip": v_zip,
    "gz": v_gzip,
    "evtx": v_evtx,
    "regf": v_regf,
}
