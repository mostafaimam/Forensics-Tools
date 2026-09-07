"""A small, defensive TIFF / EXIF / GPS IFD reader.

Works on a raw TIFF block (the payload of a JPEG ``APP1`` segment, or a
whole ``.tif`` file).  Only the tags a forensic examiner usually wants are
surfaced; everything is best-effort and never raises on malformed input.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8,
              11: 4, 12: 8, 13: 4}

# IFD0 / ExifIFD tag numbers we care about
_MAKE = 0x010F
_MODEL = 0x0110
_ORIENTATION = 0x0112
_SOFTWARE = 0x0131
_DATETIME = 0x0132
_ARTIST = 0x013B
_COPYRIGHT = 0x8298
_EXIF_IFD = 0x8769
_GPS_IFD = 0x8825
_DATETIME_ORIGINAL = 0x9003
_DATETIME_DIGITIZED = 0x9004
_OFFSET_TIME_ORIGINAL = 0x9011
_EXPOSURE_TIME = 0x829A
_FNUMBER = 0x829D
_ISO = 0x8827
_FOCAL_LENGTH = 0x920A
_LENS_MAKE = 0xA433
_LENS_MODEL = 0xA434
_BODY_SERIAL = 0xA431
_PIXEL_X = 0xA002
_PIXEL_Y = 0xA003
_IMAGE_WIDTH = 0x0100
_IMAGE_LENGTH = 0x0101
_THUMB_OFFSET = 0x0201
_THUMB_LENGTH = 0x0202
_MAKERNOTE = 0x927C
_USER_COMMENT = 0x9286

_ORIENTATION_TEXT = {
    1: "normal", 2: "mirror-h", 3: "rotate-180", 4: "mirror-v",
    5: "mirror-h+rotate-270-cw", 6: "rotate-90-cw",
    7: "mirror-h+rotate-90-cw", 8: "rotate-270-cw",
}


@dataclass
class Exif:
    make: str = ""
    model: str = ""
    lens: str = ""
    body_serial: str = ""
    software: str = ""
    artist: str = ""
    copyright: str = ""
    user_comment: str = ""
    orientation: int = 0
    orientation_text: str = ""
    datetime_original: str = ""
    datetime_digitized: str = ""
    datetime_modified: str = ""
    offset_time: str = ""
    exposure_time: str = ""
    f_number: str = ""
    iso: str = ""
    focal_length: str = ""
    pixel_x: int = 0
    pixel_y: int = 0
    gps_lat: float | None = None
    gps_lon: float | None = None
    gps_altitude: float | None = None
    gps_timestamp: str = ""
    gps_map_datum: str = ""
    has_maker_note: bool = False
    thumbnail: bytes = field(default=b"", repr=False)
    tags_seen: int = 0

    @property
    def has_gps(self) -> bool:
        return self.gps_lat is not None and self.gps_lon is not None


class _Tiff:
    def __init__(self, buf: bytes):
        self.buf = buf
        if buf[:2] == b"II":
            self.bo = "<"
        elif buf[:2] == b"MM":
            self.bo = ">"
        else:
            raise ValueError("not a TIFF header")
        (magic,) = struct.unpack(self.bo + "H", buf[2:4])
        if magic != 42:
            raise ValueError("bad TIFF magic")
        (self.ifd0,) = struct.unpack(self.bo + "I", buf[4:8])

    def _u(self, fmt: str, off: int):
        n = struct.calcsize(self.bo + fmt)
        return struct.unpack(self.bo + fmt, self.buf[off:off + n])

    def entries(self, ifd_off: int):
        """Yield ``(tag, type, count, value_bytes, next_ifd)``."""
        if ifd_off <= 0 or ifd_off + 2 > len(self.buf):
            return
        (count,) = self._u("H", ifd_off)
        base = ifd_off + 2
        end = base + count * 12
        if end + 4 > len(self.buf):
            count = max(0, (len(self.buf) - 4 - base) // 12)
            end = base + count * 12
        for i in range(count):
            e = base + i * 12
            tag, typ, cnt = self._u("HHI", e)
            size = _TYPE_SIZE.get(typ, 0) * cnt
            if size == 0:
                continue
            if size <= 4:
                raw = self.buf[e + 8:e + 8 + size]
            else:
                (ptr,) = self._u("I", e + 8)
                raw = self.buf[ptr:ptr + size]
            yield tag, typ, cnt, raw
        (nxt,) = self._u("I", end) if end + 4 <= len(self.buf) else (0,)
        self._next = nxt

    def value(self, typ: int, cnt: int, raw: bytes):
        bo = self.bo
        if typ == 2:  # ASCII
            return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        if typ in (1, 6, 7):
            return list(raw[:cnt])
        if typ == 3:  # SHORT
            return list(struct.unpack(f"{bo}{cnt}H", raw[:cnt * 2]))
        if typ in (4, 9):  # LONG / SLONG
            c = "i" if typ == 9 else "I"
            return list(struct.unpack(f"{bo}{cnt}{c}", raw[:cnt * 4]))
        if typ in (5, 10):  # RATIONAL / SRATIONAL
            c = "i" if typ == 10 else "I"
            out = []
            for k in range(cnt):
                num, den = struct.unpack(f"{bo}2{c}", raw[k * 8:k * 8 + 8])
                out.append((num, den))
            return out
        return raw


def _rat(v) -> float | None:
    try:
        num, den = v
        return num / den if den else None
    except Exception:  # noqa: BLE001
        return None


def _rat_str(v) -> str:
    try:
        num, den = v
        if not den:
            return ""
        f = num / den
        if den == 1 or f == int(f):
            return str(int(f))
        if f >= 1:
            return f"{f:.3g}"
        return f"{num}/{den}"
    except Exception:  # noqa: BLE001
        return ""


def _dms_to_deg(vals, ref: str) -> float | None:
    try:
        d = _rat(vals[0]) or 0.0
        m = _rat(vals[1]) or 0.0
        s = _rat(vals[2]) or 0.0
        deg = d + m / 60.0 + s / 3600.0
        if ref.upper() in ("S", "W"):
            deg = -deg
        return round(deg, 7)
    except Exception:  # noqa: BLE001
        return None


def _parse_gps(t: _Tiff, off: int, ex: Exif) -> None:
    raw_by_tag: dict[int, tuple] = {}
    for tag, typ, cnt, raw in t.entries(off):
        raw_by_tag[tag] = (typ, cnt, raw)
    val = {tag: t.value(typ, cnt, raw)
           for tag, (typ, cnt, raw) in raw_by_tag.items()}
    lat_ref = (val.get(1) or "N")
    lon_ref = (val.get(3) or "E")
    if 2 in val:
        ex.gps_lat = _dms_to_deg(val[2], lat_ref if isinstance(lat_ref, str)
                                 else "N")
    if 4 in val:
        ex.gps_lon = _dms_to_deg(val[4], lon_ref if isinstance(lon_ref, str)
                                 else "E")
    if 6 in val:
        alt = _rat(val[6][0]) if isinstance(val[6], list) else None
        if alt is not None:
            ref = val.get(5)
            if isinstance(ref, list) and ref and ref[0] == 1:
                alt = -alt
            ex.gps_altitude = round(alt, 2)
    if 7 in val and isinstance(val[7], list) and len(val[7]) == 3:
        h, m, s = (_rat(x) or 0 for x in val[7])
        stamp = f"{int(h):02d}:{int(m):02d}:{int(s):02d}"
        d = val.get(29)
        ex.gps_timestamp = (f"{d} {stamp}Z" if isinstance(d, str) and d
                            else stamp + "Z")
    if isinstance(val.get(18), str):
        ex.gps_map_datum = val[18]


def parse_tiff(buf: bytes) -> Exif:
    ex = Exif()
    try:
        t = _Tiff(buf)
    except Exception:  # noqa: BLE001
        return ex

    def walk(off: int, is_exif: bool = False):
        pending_exif = pending_gps = 0
        for tag, typ, cnt, raw in t.entries(off):
            ex.tags_seen += 1
            v = t.value(typ, cnt, raw)
            if tag == _MAKE and isinstance(v, str):
                ex.make = v
            elif tag == _MODEL and isinstance(v, str):
                ex.model = v
            elif tag == _LENS_MODEL and isinstance(v, str):
                ex.lens = v
            elif tag == _LENS_MAKE and isinstance(v, str) and not ex.lens:
                ex.lens = v
            elif tag == _BODY_SERIAL and isinstance(v, str):
                ex.body_serial = v
            elif tag == _SOFTWARE and isinstance(v, str):
                ex.software = v
            elif tag == _ARTIST and isinstance(v, str):
                ex.artist = v
            elif tag == _COPYRIGHT and isinstance(v, str):
                ex.copyright = v
            elif tag == _USER_COMMENT and isinstance(raw, (bytes, bytearray)):
                txt = bytes(raw)
                if txt[:8] in (b"ASCII\x00\x00\x00", b"UNICODE\x00"):
                    txt = txt[8:]
                ex.user_comment = txt.split(b"\x00", 1)[0].decode(
                    "utf-8", "replace").strip()
            elif tag == _ORIENTATION and isinstance(v, list) and v:
                ex.orientation = int(v[0])
                ex.orientation_text = _ORIENTATION_TEXT.get(int(v[0]), "")
            elif tag == _DATETIME and isinstance(v, str):
                ex.datetime_modified = v
            elif tag == _DATETIME_ORIGINAL and isinstance(v, str):
                ex.datetime_original = v
            elif tag == _DATETIME_DIGITIZED and isinstance(v, str):
                ex.datetime_digitized = v
            elif tag == _OFFSET_TIME_ORIGINAL and isinstance(v, str):
                ex.offset_time = v
            elif tag == _EXPOSURE_TIME and isinstance(v, list) and v:
                s = _rat_str(v[0])
                ex.exposure_time = (f"{s}s" if s and "/" not in s
                                    else (s + "s" if s else ""))
            elif tag == _FNUMBER and isinstance(v, list) and v:
                f = _rat(v[0])
                ex.f_number = f"f/{f:.1f}" if f else ""
            elif tag == _ISO and isinstance(v, list) and v:
                ex.iso = f"ISO {v[0]}"
            elif tag == _FOCAL_LENGTH and isinstance(v, list) and v:
                f = _rat(v[0])
                ex.focal_length = f"{f:g}mm" if f else ""
            elif tag == _PIXEL_X and isinstance(v, list) and v:
                ex.pixel_x = int(v[0])
            elif tag == _PIXEL_Y and isinstance(v, list) and v:
                ex.pixel_y = int(v[0])
            elif tag in (_IMAGE_WIDTH, _IMAGE_LENGTH) and isinstance(v, list) \
                    and v and not is_exif:
                if tag == _IMAGE_WIDTH and not ex.pixel_x:
                    ex.pixel_x = int(v[0])
                elif not ex.pixel_y:
                    ex.pixel_y = int(v[0])
            elif tag == _MAKERNOTE:
                ex.has_maker_note = True
            elif tag == _EXIF_IFD and isinstance(v, list) and v:
                pending_exif = int(v[0])
            elif tag == _GPS_IFD and isinstance(v, list) and v:
                pending_gps = int(v[0])
        if pending_exif:
            walk(pending_exif, is_exif=True)
        if pending_gps:
            try:
                _parse_gps(t, pending_gps, ex)
            except Exception:  # noqa: BLE001
                pass

    try:
        walk(t.ifd0)
    except Exception:  # noqa: BLE001
        pass

    # IFD1 thumbnail
    try:
        list(t.entries(t.ifd0))
        ifd1 = getattr(t, "_next", 0)
        if ifd1:
            off = length = 0
            for tag, typ, cnt, raw in t.entries(ifd1):
                v = t.value(typ, cnt, raw)
                if tag == _THUMB_OFFSET and isinstance(v, list) and v:
                    off = int(v[0])
                elif tag == _THUMB_LENGTH and isinstance(v, list) and v:
                    length = int(v[0])
            if off and length and off + length <= len(buf):
                cand = buf[off:off + length]
                if cand[:2] == b"\xff\xd8":
                    ex.thumbnail = cand
    except Exception:  # noqa: BLE001
        pass
    return ex
