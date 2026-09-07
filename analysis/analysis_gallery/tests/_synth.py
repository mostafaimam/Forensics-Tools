"""Synthetic media builders for the analysis_gallery test-suite.

Everything here is hand-assembled so the tests never need a real photo or a
third-party encoder.
"""

from __future__ import annotations

import struct
import zlib

# --------------------------------------------------------------------------
# TIFF / EXIF block builder
# --------------------------------------------------------------------------

_T_BYTE, _T_ASCII, _T_SHORT, _T_LONG, _T_RATIONAL = 1, 2, 3, 4, 5


def _ifd(entries: list[tuple], next_off: int, data_base: int,
         bo: str = "<") -> tuple[bytes, bytes]:
    """entries: (tag, type, values-list).  Returns (ifd_bytes, heap_bytes)."""
    heap = b""
    out = struct.pack(bo + "H", len(entries))
    fixed_len = 2 + len(entries) * 12 + 4
    for tag, typ, vals in entries:
        if typ == _T_ASCII:
            raw = vals if isinstance(vals, bytes) else vals.encode()
            raw = raw + b"\x00"
            cnt = len(raw)
            payload = raw
        elif typ == _T_SHORT:
            cnt = len(vals)
            payload = b"".join(struct.pack(bo + "H", v) for v in vals)
        elif typ == _T_LONG:
            cnt = len(vals)
            payload = b"".join(struct.pack(bo + "I", v) for v in vals)
        elif typ == _T_RATIONAL:
            cnt = len(vals)
            payload = b"".join(struct.pack(bo + "II", n, d) for n, d in vals)
        elif typ == _T_BYTE:
            cnt = len(vals)
            payload = bytes(vals)
        else:
            raise ValueError(typ)
        if len(payload) <= 4:
            value_field = payload + b"\x00" * (4 - len(payload))
        else:
            off = data_base + fixed_len + len(heap)
            value_field = struct.pack(bo + "I", off)
            heap += payload
        out += struct.pack(bo + "HHI", tag, typ, cnt) + value_field
    out += struct.pack(bo + "I", next_off)
    return out, heap


def exif_block(*, make="TestCam", model="Model X", software="",
               datetime_original="2026:08:15 14:30:00",
               orientation=1, gps=None, lens="", thumbnail: bytes | None = None,
               bo="<") -> bytes:
    """Build a raw TIFF block (what lives after 'Exif\\0\\0')."""
    head = (b"II" if bo == "<" else b"MM") + struct.pack(bo + "HI", 42, 8)
    data_base = 0  # offsets are relative to TIFF start; header is 8 bytes

    # --- GPS IFD ---
    gps_ifd = b""
    gps_heap = b""
    gps_off = 0

    # --- Exif sub-IFD ---
    exif_entries = [
        (0x9003, _T_ASCII, datetime_original),
        (0x829A, _T_RATIONAL, [(1, 200)]),        # exposure 1/200
        (0x829D, _T_RATIONAL, [(28, 10)]),        # f/2.8
        (0x8827, _T_SHORT, [400]),                # ISO
        (0x920A, _T_RATIONAL, [(50, 1)]),         # 50mm
        (0xA002, _T_LONG, [64]),
        (0xA003, _T_LONG, [48]),
    ]
    if lens:
        exif_entries.append((0xA434, _T_ASCII, lens))

    # We assemble bottom-up with a simple fixed layout:
    #   [header 8][IFD0][IFD0 heap][Exif IFD][Exif heap][GPS IFD][GPS heap]
    #   [thumb IFD (IFD1)][thumb bytes]
    ifd0_entries = [
        (0x010F, _T_ASCII, make),
        (0x0110, _T_ASCII, model),
        (0x0112, _T_SHORT, [orientation]),
        (0x0132, _T_ASCII, "2026:08:15 14:31:00"),
    ]
    if software:
        ifd0_entries.append((0x0131, _T_ASCII, software))

    # placeholder pointers, patched after we know sizes
    ifd0_entries.append((0x8769, _T_LONG, [0]))   # Exif IFD ptr  (index -2 area)
    if gps:
        ifd0_entries.append((0x8825, _T_LONG, [0]))

    # First pass: measure IFD0
    ifd0_fixed = 2 + len(ifd0_entries) * 12 + 4
    pos = 8
    ifd0_start = pos
    # compute heap size of IFD0 (ascii > 4 bytes)
    def _heap_len(entries):
        n = 0
        for tag, typ, vals in entries:
            if typ == _T_ASCII:
                raw = (vals if isinstance(vals, bytes) else vals.encode()) + b"\x00"
                if len(raw) > 4:
                    n += len(raw)
            elif typ == _T_RATIONAL:
                n += 8 * len(vals)
            elif typ == _T_SHORT and len(vals) > 2:
                n += 2 * len(vals)
            elif typ == _T_LONG and len(vals) > 1:
                n += 4 * len(vals)
        return n

    ifd0_heap_len = _heap_len(ifd0_entries)
    exif_start = ifd0_start + ifd0_fixed + ifd0_heap_len
    exif_fixed = 2 + len(exif_entries) * 12 + 4
    exif_heap_len = _heap_len(exif_entries)
    gps_start = exif_start + exif_fixed + exif_heap_len

    gps_entries = []
    if gps:
        lat, lon = gps
        latref = b"N" if lat >= 0 else b"S"
        lonref = b"E" if lon >= 0 else b"W"
        lat, lon = abs(lat), abs(lon)
        ld, lm = int(lat), int((lat % 1) * 60)
        ls = round((((lat % 1) * 60) % 1) * 60, 4)
        od, om = int(lon), int((lon % 1) * 60)
        os_ = round((((lon % 1) * 60) % 1) * 60, 4)
        gps_entries = [
            (0x0000, _T_BYTE, [2, 3, 0, 0]),
            (0x0001, _T_ASCII, latref),
            (0x0002, _T_RATIONAL, [(ld, 1), (lm, 1), (int(ls * 100), 100)]),
            (0x0003, _T_ASCII, lonref),
            (0x0004, _T_RATIONAL, [(od, 1), (om, 1), (int(os_ * 100), 100)]),
            (0x0005, _T_BYTE, [0]),
            (0x0006, _T_RATIONAL, [(1050, 100)]),
            (0x001D, _T_ASCII, "2026:08:15"),
            (0x0007, _T_RATIONAL, [(14, 1), (30, 1), (0, 1)]),
        ]
        gps_fixed = 2 + len(gps_entries) * 12 + 4
        gps_heap_len = _heap_len(gps_entries)
    else:
        gps_fixed = gps_heap_len = 0

    ifd1_start = gps_start + gps_fixed + gps_heap_len
    thumb = thumbnail or b""
    if thumb:
        ifd1_entries = [
            (0x0201, _T_LONG, [0]),   # patched
            (0x0202, _T_LONG, [len(thumb)]),
        ]
        ifd1_fixed = 2 + len(ifd1_entries) * 12 + 4
        thumb_off = ifd1_start + ifd1_fixed
    else:
        ifd1_entries = []
        ifd1_fixed = 0
        thumb_off = 0

    # patch pointers
    for i, (tag, typ, vals) in enumerate(ifd0_entries):
        if tag == 0x8769:
            ifd0_entries[i] = (tag, typ, [exif_start])
        elif tag == 0x8825:
            ifd0_entries[i] = (tag, typ, [gps_start])
    if thumb:
        ifd1_entries[0] = (0x0201, _T_LONG, [thumb_off])

    ifd1_next = 0
    ifd0_bytes, ifd0_hp = _ifd(ifd0_entries, ifd1_start if thumb else 0,
                               ifd0_start, bo)
    exif_bytes, exif_hp = _ifd(exif_entries, 0, exif_start, bo)
    gps_bytes, gps_hp = (_ifd(gps_entries, 0, gps_start, bo)
                         if gps else (b"", b""))
    ifd1_bytes, ifd1_hp = (_ifd(ifd1_entries, ifd1_next, ifd1_start, bo)
                           if thumb else (b"", b""))

    blob = (head + ifd0_bytes + ifd0_hp + exif_bytes + exif_hp
            + gps_bytes + gps_hp + ifd1_bytes + ifd1_hp + thumb)
    return blob


# --------------------------------------------------------------------------
# Baseline grayscale JPEG encoder (quant = 1, DC + EOB only)
# --------------------------------------------------------------------------

_DC_BITS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
_DC_VALS = list(range(12))
# minimal AC table for the encoder: only EOB (0x00) and ZRL (0xF0) are used
_AC_BITS = [0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
_AC_VALS = [0x00, 0xF0]


def _canon(bits, vals):
    codes = {}
    code = 0
    k = 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            codes[vals[k]] = (length, code)
            k += 1
            code += 1
        code <<= 1
    return codes


class _BW:
    def __init__(self):
        self.acc = 0
        self.n = 0
        self.out = bytearray()

    def put(self, code: int, length: int):
        self.acc = (self.acc << length) | (code & ((1 << length) - 1))
        self.n += length
        while self.n >= 8:
            self.n -= 8
            b = (self.acc >> self.n) & 0xFF
            self.out.append(b)
            if b == 0xFF:
                self.out.append(0x00)

    def flush(self):
        if self.n:
            self.put((1 << (8 - self.n)) - 1, 8 - self.n)


def _cat(v: int) -> int:
    return v.bit_length() if v >= 0 else (-v).bit_length()


def grayscale_jpeg(blocks: list[list[int]], bw_blocks: int, bh_blocks: int,
                   *, exif: bytes | None = None) -> bytes:
    """`blocks` is a bw_blocks*bh_blocks grid; each item a flat 0..255 value."""
    w = bw_blocks * 8
    h = bh_blocks * 8
    dc_codes = _canon(_DC_BITS, _DC_VALS)
    ac_codes = _canon(_AC_BITS, _AC_VALS)

    out = bytearray(b"\xff\xd8")
    if exif:
        seg = b"Exif\x00\x00" + exif
        out += b"\xff\xe1" + struct.pack(">H", len(seg) + 2) + seg
    # DQT (all ones)
    out += b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes([1] * 64)
    # SOF0
    out += b"\xff\xc0" + struct.pack(">H", 11) + bytes([8]) + struct.pack(
        ">HH", h, w) + bytes([1, 1, 0x11, 0])
    # DHT DC
    out += (b"\xff\xc4" + struct.pack(">H", 19 + len(_DC_VALS))
            + bytes([0x00]) + bytes(_DC_BITS) + bytes(_DC_VALS))
    # DHT AC
    out += (b"\xff\xc4" + struct.pack(">H", 19 + len(_AC_VALS))
            + bytes([0x10]) + bytes(_AC_BITS) + bytes(_AC_VALS))
    # SOS
    out += b"\xff\xda" + struct.pack(">H", 8) + bytes([1, 1, 0x00, 0, 63, 0])

    bw = _BW()
    prev_dc = 0
    for by in range(bh_blocks):
        for bx in range(bw_blocks):
            val = blocks[by * bw_blocks + bx]
            dc = 8 * (val - 128)          # quant = 1
            diff = dc - prev_dc
            prev_dc = dc
            cat = _cat(diff)
            length, code = dc_codes[cat]
            bw.put(code, length)
            if cat:
                mag = diff if diff >= 0 else ((1 << cat) - 1 + diff)
                bw.put(mag, cat)
            # EOB
            length, code = ac_codes[0x00]
            bw.put(code, length)
    bw.flush()
    out += bytes(bw.out)
    out += b"\xff\xd9"
    return bytes(out)


def flat_jpeg(value: int = 128, bw_blocks: int = 4, bh_blocks: int = 3,
              **kw) -> bytes:
    return grayscale_jpeg([value] * (bw_blocks * bh_blocks),
                          bw_blocks, bh_blocks, **kw)


def gradient_jpeg(bw_blocks: int = 8, bh_blocks: int = 8, **kw) -> bytes:
    grid = []
    for by in range(bh_blocks):
        for bx in range(bw_blocks):
            grid.append(int(20 + 200 * (bx / max(1, bw_blocks - 1))))
    return grayscale_jpeg(grid, bw_blocks, bh_blocks, **kw)


def pattern_jpeg(bw_blocks: int = 10, bh_blocks: int = 10, seed: int = 1,
                 **kw) -> bytes:
    grid = []
    for by in range(bh_blocks):
        for bx in range(bw_blocks):
            grid.append((bx * 37 + by * 53 + seed * 91) % 240 + 8)
    return grayscale_jpeg(grid, bw_blocks, bh_blocks, **kw)


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def rgb_png(width: int, height: int, pixel_fn=None, text=None) -> bytes:
    pixel_fn = pixel_fn or (lambda x, y: (x * 4 % 256, y * 4 % 256, 128))
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        for x in range(width):
            raw.extend(pixel_fn(x, y))
    body = b"\x89PNG\r\n\x1a\n"
    body += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height,
                                            8, 2, 0, 0, 0))
    for k, v in (text or {}).items():
        body += _png_chunk(b"tEXt", k.encode() + b"\x00" + v.encode())
    body += _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    body += _png_chunk(b"IEND", b"")
    return body


def gray_png(width: int, height: int, value_fn=None) -> bytes:
    value_fn = value_fn or (lambda x, y: (x * 255) // max(1, width - 1))
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        for x in range(width):
            raw.append(value_fn(x, y) & 0xFF)
    body = b"\x89PNG\r\n\x1a\n"
    body += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height,
                                            8, 0, 0, 0, 0))
    body += _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    body += _png_chunk(b"IEND", b"")
    return body


# --------------------------------------------------------------------------
# BMP (24-bit, bottom-up)
# --------------------------------------------------------------------------

def bmp24(width: int, height: int, pixel_fn=None) -> bytes:
    pixel_fn = pixel_fn or (lambda x, y: (x % 256, y % 256, 100))
    row_size = ((24 * width + 31) // 32) * 4
    pad = row_size - width * 3
    pix = bytearray()
    for y in range(height - 1, -1, -1):
        for x in range(width):
            r, g, b = pixel_fn(x, y)
            pix += bytes([b, g, r])
        pix += b"\x00" * pad
    data_off = 54
    size = data_off + len(pix)
    hdr = b"BM" + struct.pack("<IHHI", size, 0, 0, data_off)
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0,
                      len(pix), 2835, 2835, 0, 0)
    return hdr + dib + bytes(pix)


# --------------------------------------------------------------------------
# GIF (uncompressed-LZW trick)
# --------------------------------------------------------------------------

def gif_solid(width: int, height: int, color_index: int = 1,
              comment: str = "") -> bytes:
    palette = bytes([0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 0])
    out = bytearray(b"GIF89a")
    out += struct.pack("<HH", width, height)
    out += bytes([0xF1, 0, 0])            # GCT flag, 4 colours
    out += palette
    if comment:
        out += b"\x21\xfe"
        c = comment.encode()[:255]
        out += bytes([len(c)]) + c + b"\x00"
    out += b"\x2c" + struct.pack("<HHHH", 0, 0, width, height) + bytes([0])
    min_code = 2
    clear = 1 << min_code
    eoi = clear + 1
    code_size = min_code + 1
    bw = 0
    bn = 0
    stream = bytearray()

    def emit(code):
        nonlocal bw, bn
        bw |= code << bn
        bn += code_size
        while bn >= 8:
            stream.append(bw & 0xFF)
            bw >>= 8
            bn -= 8

    emit(clear)
    for _ in range(width * height):
        emit(color_index)
        emit(clear)          # reset the dictionary so codes stay literal
    emit(eoi)
    if bn:
        stream.append(bw & 0xFF)

    out += bytes([min_code])
    for i in range(0, len(stream), 255):
        block = stream[i:i + 255]
        out += bytes([len(block)]) + block
    out += b"\x00\x3b"
    return bytes(out)


# --------------------------------------------------------------------------
# MP4 (ftyp + moov/mvhd + trak/tkhd + udta/(c)xyz)
# --------------------------------------------------------------------------

def _box(tag: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + tag + payload


def mp4(width=1920, height=1080, duration_s=12.5, created_iso6709=None,
        creation_unix=1_600_000_000) -> bytes:
    ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 0x200)
                + b"isomiso2mp41")
    mp4_time = creation_unix + 2082844800
    timescale = 1000
    dur = int(duration_s * timescale)
    mvhd = _box(b"mvhd", struct.pack(">B3xIIII", 0, mp4_time, mp4_time,
                                     timescale, dur)
                + b"\x00\x01\x00\x00" + b"\x01\x00" + b"\x00" * 10
                + struct.pack(">9i", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0,
                              0x40000000)
                + b"\x00" * 24 + struct.pack(">I", 2))
    # tkhd: width/height are 16.16 fixed at the end
    tkhd_payload = (struct.pack(">B3x", 0) + struct.pack(">IIII", mp4_time,
                    mp4_time, 1, 0) + struct.pack(">I", dur)
                    + b"\x00" * 8 + struct.pack(">hhhh", 0, 0, 0, 0)
                    + struct.pack(">9i", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0,
                                  0x40000000)
                    + struct.pack(">II", width << 16, height << 16))
    tkhd = _box(b"tkhd", tkhd_payload)
    hdlr = _box(b"hdlr", struct.pack(">B3x", 0) + b"\x00\x00\x00\x00"
                + b"vide" + b"\x00" * 12 + b"VideoHandler\x00")
    mdia = _box(b"mdia", hdlr)
    trak = _box(b"trak", tkhd + mdia)
    udta = b""
    if created_iso6709:
        loc = created_iso6709.encode()
        xyz = struct.pack(">H", len(loc)) + b"\x15\xc7" + loc
        udta = _box(b"udta", _box(b"\xa9xyz", xyz))
    moov = _box(b"moov", mvhd + trak + udta)
    return ftyp + moov
