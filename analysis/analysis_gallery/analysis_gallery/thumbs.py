"""Build small thumbnails for the contact sheet, standard library only."""

from __future__ import annotations

import base64
import struct
import zlib

from analysis_gallery import phash


def _png_gray(grid: list[int], w: int, h: int) -> bytes:
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter: none
        raw.extend(grid[y * w:(y + 1) * w])

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def gray_thumb_datauri(grid: list[int], w: int, h: int, box: int = 160) -> str:
    if not grid or not w or not h:
        return ""
    scale = min(box / w, box / h, 1.0)
    tw = max(1, int(w * scale))
    th = max(1, int(h * scale))
    small = phash._resize_area(grid, w, h, tw, th)
    png = _png_gray(small, tw, th)
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def jpeg_thumb_datauri(jpeg_bytes: bytes) -> str:
    if not jpeg_bytes or jpeg_bytes[:2] != b"\xff\xd8":
        return ""
    return "data:image/jpeg;base64," + base64.b64encode(jpeg_bytes).decode(
        "ascii")
