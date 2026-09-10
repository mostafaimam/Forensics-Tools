"""Interpret the bytes at an offset as every common scalar / timestamp type."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timedelta, timezone

_UNIX = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FILETIME = datetime(1601, 1, 1, tzinfo=timezone.utc)
_OLE = datetime(1899, 12, 30, tzinfo=timezone.utc)
_COCOA = datetime(2001, 1, 1, tzinfo=timezone.utc)
_HFS = datetime(1904, 1, 1, tzinfo=timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sane(dt: datetime) -> bool:
    return datetime(1980, 1, 1, tzinfo=timezone.utc) <= dt <= \
        datetime(2100, 1, 1, tzinfo=timezone.utc)


def _try(fn):
    try:
        return fn()
    except (ValueError, OverflowError, OSError, struct.error):
        return None


def _times(u32: int | None, u64: int | None) -> dict:
    out: dict[str, str] = {}

    def add(label, dt):
        if dt is not None and _sane(dt):
            out[label] = _fmt(dt)

    if u32 is not None:
        add("unix_s", _try(lambda: _UNIX + timedelta(seconds=u32)))
        add("hfs+", _try(lambda: _HFS + timedelta(seconds=u32)))
        dos = _try(lambda: _dos(u32))
        if dos:
            out["dos"] = dos
    if u64 is not None:
        add("filetime", _try(lambda: _FILETIME + timedelta(
            microseconds=u64 // 10)))
        add("unix_ms", _try(lambda: _UNIX + timedelta(
            milliseconds=u64)))
        add("unix_us", _try(lambda: _UNIX + timedelta(microseconds=u64)))
        add("webkit/chrome", _try(lambda: _FILETIME + timedelta(
            microseconds=u64)))
    return out


def _dos(v: int) -> str | None:
    date = v >> 16
    time = v & 0xFFFF
    y = ((date >> 9) & 0x7F) + 1980
    mo = (date >> 5) & 0x0F
    d = date & 0x1F
    hh = (time >> 11) & 0x1F
    mm = (time >> 5) & 0x3F
    ss = (time & 0x1F) * 2
    if not (1 <= mo <= 12 and 1 <= d <= 31 and hh < 24 and mm < 60):
        return None
    return f"{y:04d}-{mo:02d}-{d:02d}T{hh:02d}:{mm:02d}:{ss:02d}"


def interpret(buf: bytes, off: int) -> dict:
    """Return {representation: value} for the bytes starting at buf[off]."""
    r: dict = {"offset": off, "offset_hex": f"{off:#x}"}
    w = buf[off:off + 8]
    if not w:
        return r
    r["hex"] = w.hex(" ")
    r["ascii"] = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in w)

    def g(fmt, n):
        return _try(lambda: struct.unpack_from(fmt, buf, off)[0]) \
            if off + n <= len(buf) else None

    r["int8"] = g("<b", 1)
    r["uint8"] = g("<B", 1)
    r["int16_le"] = g("<h", 2)
    r["uint16_le"] = g("<H", 2)
    r["int16_be"] = g(">h", 2)
    r["uint16_be"] = g(">H", 2)
    r["int32_le"] = g("<i", 4)
    r["uint32_le"] = g("<I", 4)
    r["int32_be"] = g(">i", 4)
    r["uint32_be"] = g(">I", 4)
    r["int64_le"] = g("<q", 8)
    r["uint64_le"] = g("<Q", 8)
    r["int64_be"] = g(">q", 8)
    r["uint64_be"] = g(">Q", 8)
    r["float_le"] = g("<f", 4)
    r["float_be"] = g(">f", 4)
    r["double_le"] = g("<d", 8)
    r["double_be"] = g(">d", 8)

    if off + 16 <= len(buf):
        r["guid_le"] = str(uuid.UUID(bytes_le=buf[off:off + 16]))
        r["guid_be"] = str(uuid.UUID(bytes=buf[off:off + 16]))
    if off + 3 <= len(buf):
        rgb = buf[off:off + 3]
        r["rgb"] = f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
    if off + 4 <= len(buf):
        rgba = buf[off:off + 4]
        r["rgba"] = "#" + rgba.hex()

    ole = r["double_le"]
    if isinstance(ole, float) and -100000 < ole < 100000:
        dt = _try(lambda: _OLE + timedelta(days=ole))
        if dt and _sane(dt):
            r["ole_date"] = _fmt(dt)
    cocoa = r["double_le"]
    if isinstance(cocoa, float) and abs(cocoa) < 4e9:
        dt = _try(lambda: _COCOA + timedelta(seconds=cocoa))
        if dt and _sane(dt):
            r["cocoa_date"] = _fmt(dt)
    r["timestamps"] = _times(r["uint32_le"], r["uint64_le"])
    # keep only populated scalar keys
    return {k: v for k, v in r.items() if v is not None and v != {}}
