"""Uncompressed BMP / DIB reader: dimensions and a grayscale decode."""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class BmpInfo:
    width: int = 0
    height: int = 0
    bpp: int = 0
    compression: int = 0


def info(buf: bytes) -> BmpInfo:
    out = BmpInfo()
    if buf[:2] != b"BM" or len(buf) < 54:
        return out
    (hdr_size,) = struct.unpack("<I", buf[14:18])
    if hdr_size >= 40:
        w, h = struct.unpack("<ii", buf[18:26])
        (planes, bpp) = struct.unpack("<HH", buf[26:30])
        (comp,) = struct.unpack("<I", buf[30:34])
        out.width, out.height = abs(w), abs(h)
        out.bpp, out.compression = bpp, comp
    elif hdr_size == 12:
        w, h = struct.unpack("<HH", buf[18:22])
        (planes, bpp) = struct.unpack("<HH", buf[22:26])
        out.width, out.height, out.bpp = w, h, bpp
    return out


def decode_gray(buf: bytes):
    meta = info(buf)
    if not meta.width or not meta.height or meta.compression not in (0, 3):
        return None
    (data_off,) = struct.unpack("<I", buf[10:14])
    (hdr_size,) = struct.unpack("<I", buf[14:18])
    top_down = False
    if hdr_size >= 40:
        (_, h) = struct.unpack("<ii", buf[18:26])
        top_down = h < 0
    w, h = meta.width, meta.height
    bpp = meta.bpp
    row_size = ((bpp * w + 31) // 32) * 4
    pal_off = 14 + hdr_size
    palette = []
    if bpp <= 8:
        pal_entries = (data_off - pal_off) // 4
        for k in range(min(pal_entries, 1 << bpp)):
            b, g, r, _ = buf[pal_off + k * 4:pal_off + k * 4 + 4]
            palette.append((r * 299 + g * 587 + b * 114) // 1000)

    grid = [0] * (w * h)
    try:
        for y in range(h):
            src_y = y if top_down else (h - 1 - y)
            base = data_off + src_y * row_size
            row = buf[base:base + row_size]
            for x in range(w):
                if bpp == 24 or bpp == 32:
                    o = x * (bpp // 8)
                    b, g, r = row[o], row[o + 1], row[o + 2]
                    v = (r * 299 + g * 587 + b * 114) // 1000
                elif bpp == 8:
                    v = palette[row[x]] if row[x] < len(palette) else row[x]
                elif bpp == 4:
                    nyb = (row[x // 2] >> (4 if x % 2 == 0 else 0)) & 0x0F
                    v = palette[nyb] if nyb < len(palette) else nyb * 17
                elif bpp == 1:
                    bit = (row[x // 8] >> (7 - x % 8)) & 1
                    v = palette[bit] if bit < len(palette) else bit * 255
                else:
                    v = 0
                grid[y * w + x] = v
    except Exception:  # noqa: BLE001
        return None
    return grid, w, h
