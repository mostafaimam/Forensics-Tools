"""Minimal PNG reader: dimensions, text metadata, and a grayscale decode.

Supports the common colour types (0/2/3/4/6) at bit depths 8 and 16, plus
1/2/4-bit greyscale and palette.  Adam7 interlacing is decoded.  Returns a
downscalable grayscale grid for hashing / thumbnails.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field


@dataclass
class PngInfo:
    width: int = 0
    height: int = 0
    bit_depth: int = 0
    color_type: int = 0
    interlace: int = 0
    text: dict[str, str] = field(default_factory=dict)


_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def _chunks(buf: bytes):
    i = 8
    n = len(buf)
    while i + 8 <= n:
        (ln,) = struct.unpack(">I", buf[i:i + 4])
        typ = buf[i + 4:i + 8]
        data = buf[i + 8:i + 8 + ln]
        yield typ.decode("latin-1"), data
        i += 12 + ln
        if typ == b"IEND":
            return


def info(buf: bytes) -> PngInfo:
    out = PngInfo()
    for typ, data in _chunks(buf):
        if typ == "IHDR" and len(data) >= 13:
            (out.width, out.height, out.bit_depth, out.color_type,
             _comp, _filt, out.interlace) = struct.unpack(">IIBBBBB", data[:13])
        elif typ in ("tEXt", "zTXt"):
            key, _, rest = data.partition(b"\x00")
            if typ == "zTXt":
                rest = rest[1:]
                try:
                    rest = zlib.decompress(rest)
                except Exception:  # noqa: BLE001
                    rest = b""
            out.text[key.decode("latin-1", "replace")] = rest.decode(
                "latin-1", "replace")
        elif typ == "iTXt":
            try:
                key, rest = data.split(b"\x00", 1)
                comp_flag = rest[0]
                rest = rest[1:]
                _cm = rest[0]
                rest = rest[1:]
                _lang, rest = rest.split(b"\x00", 1)
                _tkey, rest = rest.split(b"\x00", 1)
                if comp_flag:
                    rest = zlib.decompress(rest)
                out.text[key.decode("utf-8", "replace")] = rest.decode(
                    "utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
        elif typ == "eXIf":
            out.text.setdefault("_exif_len", str(len(data)))
    return out


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _unfilter(raw: bytes, height: int, stride: int, bpp: int) -> bytearray:
    mv = memoryview(raw)
    rowlen = stride + 1
    # fast path: every scanline uses filter 0 -> the data is already raw
    if len(raw) >= height * rowlen and all(
            raw[y * rowlen] == 0 for y in range(height)):
        out = bytearray(height * stride)
        for y in range(height):
            src = y * rowlen + 1
            out[y * stride:(y + 1) * stride] = mv[src:src + stride]
        return out

    out = bytearray(height * stride)
    prev = [0] * stride
    pos = 0
    n = len(raw)
    rng_bpp = range(bpp, stride)
    rng_all = range(stride)
    for y in range(height):
        if pos >= n:
            break
        ft = raw[pos]
        pos += 1
        line = list(mv[pos:pos + stride])
        if len(line) < stride:
            line.extend([0] * (stride - len(line)))
        pos += stride
        if ft == 0:
            pass
        elif ft == 1:
            for x in rng_bpp:
                line[x] = (line[x] + line[x - bpp]) & 0xFF
        elif ft == 2:
            for x in rng_all:
                line[x] = (line[x] + prev[x]) & 0xFF
        elif ft == 3:
            for x in range(bpp):
                line[x] = (line[x] + (prev[x] >> 1)) & 0xFF
            for x in rng_bpp:
                line[x] = (line[x] + ((line[x - bpp] + prev[x]) >> 1)) & 0xFF
        elif ft == 4:
            for x in range(bpp):
                line[x] = (line[x] + prev[x]) & 0xFF
            for x in rng_bpp:
                a = line[x - bpp]
                b = prev[x]
                c = prev[x - bpp]
                p = a + b - c
                pa = p - a if p >= a else a - p
                pb = p - b if p >= b else b - p
                pc = p - c if p >= c else c - p
                if pa <= pb and pa <= pc:
                    line[x] = (line[x] + a) & 0xFF
                elif pb <= pc:
                    line[x] = (line[x] + b) & 0xFF
                else:
                    line[x] = (line[x] + c) & 0xFF
        out[y * stride:(y + 1) * stride] = bytes(line)
        prev = line
    return out


_ADAM7 = [
    (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
    (0, 2, 2, 2), (1, 0, 2, 1), (0, 1, 1, 1),
]


def decode_gray(buf: bytes):
    """Return ``(grid, w, h)`` grayscale 0..255 row-major, or None."""
    meta = info(buf)
    if not meta.width or not meta.height:
        return None
    if meta.color_type not in _CHANNELS:
        return None
    idat = b"".join(d for t, d in _chunks(buf) if t == "IDAT")
    plte = next((d for t, d in _chunks(buf) if t == "PLTE"), b"")
    try:
        raw = zlib.decompress(idat)
    except Exception:  # noqa: BLE001
        return None

    ch = _CHANNELS[meta.color_type]
    bd = meta.bit_depth
    w, h = meta.width, meta.height

    def to_gray_rows(pix_rows):
        g = []
        for row in pix_rows:
            g.extend(row)
        return g

    def expand_scanlines(data: bytes, sw: int, sh: int):
        bits = ch * bd
        stride = (sw * bits + 7) // 8
        bpp = max(1, bits // 8)
        planes = _unfilter(data, sh, stride, bpp)
        rows = []
        for y in range(sh):
            base = y * stride
            row_samples = []
            if bd == 8:
                for x in range(sw):
                    off = base + x * ch
                    row_samples.append(tuple(planes[off:off + ch]))
            elif bd == 16:
                for x in range(sw):
                    off = base + x * ch * 2
                    row_samples.append(tuple(
                        planes[off + k * 2] for k in range(ch)))
            else:  # sub-byte greyscale / palette
                per = 8 // bd
                maxv = (1 << bd) - 1
                for x in range(sw):
                    byte = planes[base + x // per]
                    sh_ = (per - 1 - (x % per)) * bd
                    v = (byte >> sh_) & maxv
                    if meta.color_type == 3:
                        row_samples.append((v,))
                    else:
                        row_samples.append((int(v * 255 / maxv),))
            rows.append(row_samples)
        return rows

    def sample_to_gray(s: tuple) -> int:
        if meta.color_type == 3:  # palette index
            idx = s[0] * 3
            if idx + 2 < len(plte):
                r, gg, b = plte[idx], plte[idx + 1], plte[idx + 2]
                return (r * 299 + gg * 587 + b * 114) // 1000
            return s[0]
        if meta.color_type in (0, 4):
            return s[0]
        r, gg, b = s[0], s[1], s[2]
        return (r * 299 + gg * 587 + b * 114) // 1000

    grid = [0] * (w * h)
    try:
        if meta.interlace == 1:
            pos = 0
            for (ox, oy, sx, sy) in _ADAM7:
                pw = (w - ox + sx - 1) // sx
                ph = (h - oy + sy - 1) // sy
                if pw <= 0 or ph <= 0:
                    continue
                bits = ch * bd
                stride = (pw * bits + 7) // 8
                need = ph * (stride + 1)
                sub = raw[pos:pos + need]
                pos += need
                rows = expand_scanlines(sub, pw, ph)
                for j, row in enumerate(rows):
                    for k, s in enumerate(row):
                        gx = ox + k * sx
                        gy = oy + j * sy
                        if gx < w and gy < h:
                            grid[gy * w + gx] = sample_to_gray(s)
        else:
            rows = expand_scanlines(raw, w, h)
            for y, row in enumerate(rows):
                for x, s in enumerate(row):
                    grid[y * w + x] = sample_to_gray(s)
    except Exception:  # noqa: BLE001
        return None
    return grid, w, h
