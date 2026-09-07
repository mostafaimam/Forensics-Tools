"""JPEG helpers: dimensions, embedded EXIF, and a DC-only baseline decoder.

The decoder reconstructs only the DC coefficient of every 8x8 block, which
gives an image downscaled 8x - more than enough for a perceptual hash or a
contact-sheet thumbnail, at a fraction of the cost of a full IDCT.  It
covers baseline (SOF0) and the DC pass of progressive (SOF2) streams.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class JpegInfo:
    width: int = 0
    height: int = 0
    progressive: bool = False
    components: int = 0
    precision: int = 8
    exif: bytes = b""


def _segments(buf: bytes):
    i = 2
    n = len(buf)
    while i + 4 <= n:
        if buf[i] != 0xFF:
            i += 1
            continue
        marker = buf[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            i += 2
            continue
        (ln,) = struct.unpack(">H", buf[i + 2:i + 4])
        yield marker, buf[i + 4:i + 2 + ln]
        i += 2 + ln
        if marker == 0xDA:  # start of scan - entropy data follows
            return


def info(buf: bytes) -> JpegInfo:
    out = JpegInfo()
    for marker, body in _segments(buf):
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if len(body) >= 6:
                out.precision = body[0]
                out.height, out.width, out.components = struct.unpack(
                    ">HHB", body[1:6])
                out.progressive = marker in (0xC2, 0xC6, 0xCA, 0xCE)
        elif marker == 0xE1 and body[:6] == b"Exif\x00\x00":
            out.exif = body[6:]
    return out


def embedded_exif(buf: bytes) -> bytes:
    for marker, body in _segments(buf):
        if marker == 0xE1 and body[:6] == b"Exif\x00\x00":
            return body[6:]
    return b""


# --------------------------------------------------------------------------
# DC-only decoder: byte-unstuffed stream + 8-bit Huffman lookup table
# --------------------------------------------------------------------------

def _extend(v: int, t: int) -> int:
    return v - (1 << t) + 1 if v < (1 << (t - 1)) else v


class _Huff:
    __slots__ = ("lut", "long")

    def __init__(self, counts, symbols):
        self.lut = [(0, 0)] * 256           # peek8 -> (symbol, code length)
        self.long: dict[tuple[int, int], int] = {}
        code = 0
        k = 0
        for length in range(1, 17):
            for _ in range(counts[length - 1]):
                sym = symbols[k]
                k += 1
                if length <= 8:
                    lo = code << (8 - length)
                    for pre in range(lo, lo + (1 << (8 - length))):
                        self.lut[pre] = (sym, length)
                else:
                    self.long[(length, code)] = sym
                code += 1
            code <<= 1


class _Bits:
    __slots__ = ("d", "n", "pos", "acc", "cnt")

    def __init__(self, data: bytes):
        self.d = data
        self.n = len(data)
        self.pos = 0
        self.acc = 0
        self.cnt = 0

    def _fill(self):
        d = self.d
        while self.cnt <= 24 and self.pos < self.n:
            self.acc = (self.acc << 8) | d[self.pos]
            self.pos += 1
            self.cnt += 8

    def peek8(self) -> int:
        if self.cnt < 8:
            self._fill()
        c = self.cnt
        if c < 8:
            return (self.acc << (8 - c)) & 0xFF if c else 0
        return (self.acc >> (c - 8)) & 0xFF

    def drop(self, k: int):
        self.cnt -= k
        if self.cnt <= 0:
            self.cnt = 0
            self.acc = 0
        else:
            self.acc &= (1 << self.cnt) - 1

    def receive(self, k: int) -> int:
        if k == 0:
            return 0
        while self.cnt < k:
            if self.pos >= self.n:
                self.acc <<= (k - self.cnt)
                self.cnt = k
                break
            self.acc = (self.acc << 8) | self.d[self.pos]
            self.pos += 1
            self.cnt += 8
        self.cnt -= k
        v = (self.acc >> self.cnt) & ((1 << k) - 1)
        self.acc &= (1 << self.cnt) - 1
        return v

    def decode(self, huff: _Huff) -> int:
        sym, length = huff.lut[self.peek8()]
        if length:
            self.drop(length)
            return sym
        code = self.receive(8)
        for length in range(9, 17):
            code = (code << 1) | self.receive(1)
            s = huff.long.get((length, code))
            if s is not None:
                return s
        return 0

    def align_to_marker(self):
        self.acc = 0
        self.cnt = 0
        while self.pos + 1 < self.n:
            if self.d[self.pos] == 0xFF and 0xD0 <= self.d[self.pos + 1] <= 0xD7:
                self.pos += 2
                return
            self.pos += 1


def _unstuff(buf: bytes, start: int) -> bytes:
    out = bytearray()
    i = start
    n = len(buf)
    while i < n:
        b = buf[i]
        if b != 0xFF:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        nxt = buf[i + 1]
        if nxt == 0x00:
            out.append(0xFF)
            i += 2
        elif 0xD0 <= nxt <= 0xD7:
            out += buf[i:i + 2]
            i += 2
        else:
            break
    return bytes(out)


def _clamp(v: float) -> int:
    return 0 if v < 0 else (255 if v > 255 else int(v))


def decode_dc(buf: bytes):
    """Return ``(grid, gw, gh)`` - luma DC image 0..255 row-major, or None."""
    qtables: dict[int, list] = {}
    huff_dc: dict[int, _Huff] = {}
    huff_ac: dict[int, _Huff] = {}
    frame = None
    restart = 0
    scan_start = None
    scan_spec = None

    i = 2
    n = len(buf)
    while i + 4 <= n:
        if buf[i] != 0xFF:
            i += 1
            continue
        marker = buf[i + 1]
        if marker == 0xD9:
            break
        if marker == 0xD8 or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            i += 2
            continue
        (ln,) = struct.unpack(">H", buf[i + 2:i + 4])
        body = buf[i + 4:i + 2 + ln]
        if marker == 0xDB:
            p = 0
            while p < len(body):
                pq_tq = body[p]
                p += 1
                if pq_tq >> 4:
                    p += 128
                else:
                    qtables[pq_tq & 0x0F] = list(body[p:p + 64])
                    p += 64
        elif marker == 0xC4:
            p = 0
            while p + 17 <= len(body):
                tc_th = body[p]
                p += 1
                counts = list(body[p:p + 16])
                p += 16
                total = sum(counts)
                symbols = list(body[p:p + total])
                p += total
                tbl = _Huff(counts, symbols)
                (huff_ac if tc_th >> 4 else huff_dc)[tc_th & 0x0F] = tbl
        elif marker == 0xDD:
            (restart,) = struct.unpack(">H", body[:2])
        elif marker in (0xC0, 0xC1, 0xC2):
            prec, h, w, nc = struct.unpack(">BHHB", body[:6])
            comps = []
            p = 6
            for _ in range(nc):
                comps.append((body[p], body[p + 1] >> 4, body[p + 1] & 0x0F,
                              body[p + 2]))
                p += 3
            frame = (w, h, comps, marker == 0xC2)
        elif marker == 0xDA:
            ns = body[0]
            p = 1
            sel = []
            for _ in range(ns):
                sel.append((body[p], body[p + 1] >> 4, body[p + 1] & 0x0F))
                p += 2
            ss, se, ah_al = body[p], body[p + 1], body[p + 2]
            scan_spec = (sel, ss, se, ah_al >> 4, ah_al & 0x0F)
            scan_start = i + 2 + ln
            break
        i += 2 + ln

    if frame is None or scan_start is None or not huff_dc:
        return None
    w, h, comps, progressive = frame
    sel, ss, se, ah, al = scan_spec
    if progressive and not (ss == 0 and se == 0):
        return None
    if not w or not h or w * h > 500_000_000:
        return None

    hmax = max(c[1] for c in comps) or 1
    vmax = max(c[2] for c in comps) or 1
    mcux = (w + 8 * hmax - 1) // (8 * hmax)
    mcuy = (h + 8 * vmax - 1) // (8 * vmax)
    luma_id = comps[0][0]
    if luma_id not in {s[0] for s in sel}:
        return None
    interleaved = len(sel) > 1
    comp_by_id = {c[0]: c for c in comps}
    td = {s[0]: s[1] for s in sel}
    ta = {s[0]: s[2] for s in sel}
    _, lh, lv, lq = comp_by_id[luma_id]
    gw, gh = mcux * lh, mcuy * lv
    grid = bytearray(b"\x80" * (gw * gh))
    qdc = (qtables.get(lq) or [1])[0] or 1

    bits = _Bits(_unstuff(buf, scan_start))
    pred = {c[0]: 0 for c in comps}
    if td.get(luma_id, 0) not in huff_dc:
        return None

    def consume_ac(cid):
        ac = huff_ac.get(ta.get(cid, 0))
        if ac is None:
            return
        k = 1
        while k < 64:
            rs = bits.decode(ac)
            r, s2 = rs >> 4, rs & 0x0F
            if s2 == 0:
                if r != 15:
                    break
                k += 16
                continue
            k += r
            if k >= 64:
                break
            bits.receive(s2)
            k += 1

    def block(cid, xy):
        t = bits.decode(huff_dc[td[cid]])
        diff = _extend(bits.receive(t), t) if t else 0
        pred[cid] += diff
        if not progressive:
            consume_ac(cid)
        if xy is not None:
            gx, gy = xy
            if gx < gw and gy < gh:
                base = (pred[cid] << al) if progressive else pred[cid]
                grid[gy * gw + gx] = _clamp(base * qdc / 8.0 + 128.0)

    try:
        for mcu in range(mcux * mcuy):
            if restart and mcu and mcu % restart == 0:
                bits.align_to_marker()
                for cid in pred:
                    pred[cid] = 0
            my, mx = divmod(mcu, mcux)
            if interleaved:
                for (cid, ch, cv, cq) in comps:
                    for by in range(cv):
                        for bx in range(ch):
                            if cid == luma_id:
                                block(cid, (mx * lh + bx, my * lv + by))
                            else:
                                block(cid, None)
            else:
                block(luma_id, (mx, my))
    except Exception:  # noqa: BLE001
        pass

    tw = min((w + 7) // 8, gw) or gw
    th = min((h + 7) // 8, gh) or gh
    return [grid[y * gw + x] for y in range(th) for x in range(tw)], tw, th
