"""GIF reader: logical-screen dimensions and a first-frame grayscale decode."""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class GifInfo:
    width: int = 0
    height: int = 0
    frames_seen: int = 0
    comment: str = ""


def info(buf: bytes) -> GifInfo:
    out = GifInfo()
    if buf[:6] not in (b"GIF87a", b"GIF89a") or len(buf) < 13:
        return out
    out.width, out.height = struct.unpack("<HH", buf[6:10])
    # quick scan for frame count / comment (best effort)
    flags = buf[10]
    gct = 3 * (2 << (flags & 7)) if flags & 0x80 else 0
    i = 13 + gct
    n = len(buf)
    try:
        while i < n:
            b = buf[i]
            if b == 0x3B:
                break
            if b == 0x2C:
                out.frames_seen += 1
                i += 10
                lf = buf[i - 1]
                if lf & 0x80:
                    i += 3 * (2 << (lf & 7))
                i += 1  # LZW min code size
                while i < n and buf[i]:
                    i += buf[i] + 1
                i += 1
            elif b == 0x21:
                label = buf[i + 1]
                i += 2
                sub = b""
                while i < n and buf[i]:
                    sub += buf[i + 1:i + 1 + buf[i]]
                    i += buf[i] + 1
                i += 1
                if label == 0xFE:
                    out.comment = sub.decode("latin-1", "replace").strip()
            else:
                i += 1
    except Exception:  # noqa: BLE001
        pass
    return out


def _lzw_decode(data: bytes, min_code: int, expected: int) -> list[int]:
    clear = 1 << min_code
    end = clear + 1
    code_size = min_code + 1
    dict_: list[list[int]] = [[i] for i in range(clear)] + [[], []]
    out: list[int] = []
    buf = 0
    bits = 0
    prev: list[int] | None = None
    for byte in data:
        buf |= byte << bits
        bits += 8
        while bits >= code_size:
            code = buf & ((1 << code_size) - 1)
            buf >>= code_size
            bits -= code_size
            if code == clear:
                dict_ = [[i] for i in range(clear)] + [[], []]
                code_size = min_code + 1
                prev = None
                continue
            if code == end:
                return out
            if code < len(dict_):
                entry = dict_[code]
            elif prev is not None:
                entry = prev + prev[:1]
            else:
                return out
            out.extend(entry)
            if prev is not None:
                dict_.append(prev + entry[:1])
                if len(dict_) >= (1 << code_size) and code_size < 12:
                    code_size += 1
            prev = entry
            if len(out) >= expected:
                return out
    return out


def decode_gray(buf: bytes):
    meta = info(buf)
    if not meta.width or not meta.height:
        return None
    flags = buf[10]
    has_gct = bool(flags & 0x80)
    gct_size = 2 << (flags & 7)
    i = 13
    gct = []
    if has_gct:
        for k in range(gct_size):
            r, g, b = buf[i:i + 3]
            gct.append((r * 299 + g * 587 + b * 114) // 1000)
            i += 3
    n = len(buf)
    try:
        while i < n:
            b = buf[i]
            if b == 0x21:  # extension - skip
                i += 2
                while i < n and buf[i]:
                    i += buf[i] + 1
                i += 1
                continue
            if b == 0x2C:  # image descriptor
                x, y, iw, ih = struct.unpack("<HHHH", buf[i + 1:i + 9])
                lf = buf[i + 9]
                i += 10
                local = []
                if lf & 0x80:
                    lsz = 2 << (lf & 7)
                    for k in range(lsz):
                        r, g, bl = buf[i:i + 3]
                        local.append((r * 299 + g * 587 + bl * 114) // 1000)
                        i += 3
                palette = local or gct
                min_code = buf[i]
                i += 1
                lzw = bytearray()
                while i < n and buf[i]:
                    lzw += buf[i + 1:i + 1 + buf[i]]
                    i += buf[i] + 1
                i += 1
                idx = _lzw_decode(bytes(lzw), min_code, iw * ih)
                w, h = meta.width, meta.height
                grid = [0] * (w * h)
                interlaced = bool(lf & 0x40)
                order = _interlace_rows(ih) if interlaced else range(ih)
                for row_i, gy in enumerate(order):
                    for gx in range(iw):
                        p = row_i * iw + gx
                        if p >= len(idx):
                            break
                        ci = idx[p]
                        val = palette[ci] if ci < len(palette) else ci
                        px, py = x + gx, y + gy
                        if px < w and py < h:
                            grid[py * w + px] = val
                return grid, w, h
            break
    except Exception:  # noqa: BLE001
        return None
    return None


def _interlace_rows(h: int):
    rows = []
    for start, step in ((0, 8), (4, 8), (2, 4), (1, 2)):
        rows.extend(range(start, h, step))
    return rows
