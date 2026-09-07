"""Format-agnostic access to raster dimensions and a grayscale grid."""

from __future__ import annotations

import struct

from analysis_gallery import bmp, gif, jpeg, png


def dimensions(kind: str, buf: bytes) -> tuple[int, int]:
    try:
        if kind == "jpeg":
            j = jpeg.info(buf)
            return j.width, j.height
        if kind == "png":
            p = png.info(buf)
            return p.width, p.height
        if kind == "gif":
            g = gif.info(buf)
            return g.width, g.height
        if kind == "bmp":
            b = bmp.info(buf)
            return b.width, b.height
        if kind == "webp":
            return _webp_dims(buf)
        if kind == "tiff":
            return _tiff_dims(buf)
        if kind in ("heif",):
            return _heif_dims(buf)
        if kind == "ico":
            if len(buf) >= 8:
                w = buf[6] or 256
                h = buf[7] or 256
                return w, h
    except Exception:  # noqa: BLE001
        pass
    return 0, 0


def gray_grid(kind: str, buf: bytes):
    """Return ``(grid, w, h)`` grayscale, or None when the format cannot be
    decoded with the standard library."""
    try:
        if kind == "jpeg":
            r = jpeg.decode_dc(buf)
            if r:
                return r
        elif kind == "png":
            return png.decode_gray(buf)
        elif kind == "gif":
            return gif.decode_gray(buf)
        elif kind == "bmp":
            return bmp.decode_gray(buf)
    except Exception:  # noqa: BLE001
        return None
    return None


def _webp_dims(buf: bytes) -> tuple[int, int]:
    if buf[:4] != b"RIFF" or buf[8:12] != b"WEBP":
        return 0, 0
    fourcc = buf[12:16]
    if fourcc == b"VP8 ":
        # lossy: 10-byte frame header after the chunk header
        b = buf[20:30]
        if b[3:6] == b"\x9d\x01\x2a":
            w = struct.unpack("<H", b[6:8])[0] & 0x3FFF
            h = struct.unpack("<H", b[8:10])[0] & 0x3FFF
            return w, h
    elif fourcc == b"VP8L":
        b = buf[21:26]
        if b and b[0] == 0x2F:
            bits = int.from_bytes(b[1:5], "little")
            w = (bits & 0x3FFF) + 1
            h = ((bits >> 14) & 0x3FFF) + 1
            return w, h
    elif fourcc == b"VP8X":
        w = int.from_bytes(buf[24:27], "little") + 1
        h = int.from_bytes(buf[27:30], "little") + 1
        return w, h
    return 0, 0


def _tiff_dims(buf: bytes) -> tuple[int, int]:
    bo = "<" if buf[:2] == b"II" else ">"
    (off,) = struct.unpack(bo + "I", buf[4:8])
    if off + 2 > len(buf):
        return 0, 0
    (count,) = struct.unpack(bo + "H", buf[off:off + 2])
    w = h = 0
    for i in range(count):
        e = off + 2 + i * 12
        if e + 12 > len(buf):
            break
        tag, typ, cnt = struct.unpack(bo + "HHI", buf[e:e + 8])
        if tag in (0x0100, 0x0101):
            if typ == 3:
                (val,) = struct.unpack(bo + "H", buf[e + 8:e + 10])
            else:
                (val,) = struct.unpack(bo + "I", buf[e + 8:e + 12])
            if tag == 0x0100:
                w = val
            else:
                h = val
    return w, h


def _heif_dims(buf: bytes) -> tuple[int, int]:
    # walk ISO-BMFF for meta/iprp/ipco/ispe
    i = 0
    n = len(buf)
    target = b"ispe"
    while i + 8 <= n:
        size = int.from_bytes(buf[i:i + 4], "big")
        typ = buf[i + 4:i + 8]
        if size == 1:
            size = int.from_bytes(buf[i + 8:i + 16], "big")
            body = i + 16
        else:
            body = i + 8
        if typ == target and body + 12 <= n:
            w = int.from_bytes(buf[body + 4:body + 8], "big")
            h = int.from_bytes(buf[body + 8:body + 12], "big")
            return w, h
        if typ in (b"meta", b"iprp", b"ipco"):
            i = body + (4 if typ == b"meta" else 0)
            continue
        if size <= 0:
            break
        i += size
    return 0, 0
