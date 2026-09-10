"""Parse OLE property sets (SummaryInformation / DocumentSummaryInformation).

[MS-OLEPS].  A property-set stream is::

    0x00  u16 byte order (0xFFFE)
    0x02  u16 format version
    0x04  u32 os
    0x08  16  CLSID
    0x18  u32 number of property sets
    0x1c  16  FMTID0
    0x2c  u32 offset0  (to the PropertySet section)
    ...   (a second FMTID/offset for DocumentSummaryInformation user props)

PropertySet::  u32 size, u32 count, then count x (u32 id, u32 offset),
then the typed values (u16 type, u16 pad, value).
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_SUMMARY = {
    2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments",
    7: "template", 8: "last_saved_by", 9: "revision_number",
    10: "total_edit_time", 11: "last_printed", 12: "created",
    13: "last_saved", 14: "page_count", 15: "word_count",
    16: "char_count", 18: "application", 19: "security",
}
_DOCSUMMARY = {
    2: "category", 3: "presentation_format", 4: "byte_count", 5: "line_count",
    6: "paragraph_count", 7: "slide_count", 8: "note_count", 9: "hidden_count",
    11: "scale", 13: "heading_pairs", 14: "manager", 15: "company",
    17: "content_type", 18: "content_status", 19: "language", 23: "version",
}
_FMTID_SUMMARY = "f29f85e0-4ff9-1068-ab91-08002b27b3d9"
_FMTID_DOCSUMMARY = "d5cdd502-2e9c-101b-9397-08002b2cf9ae"


def _guid(b: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, b[8:10].hex(), b[10:16].hex())


def _filetime(v: int) -> str:
    if v <= 0 or v > 0x7FFF_FFFF_FFFF_FFFF:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=v // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


def _duration(v: int) -> str:
    """VT_FILETIME used as an elapsed time (total edit time)."""
    secs = v // 10_000_000
    if secs <= 0 or secs > 60 * 60 * 24 * 3650:
        return "0:00:00" if secs == 0 else ""
    return str(timedelta(seconds=secs))


def _read_value(data: bytes, off: int, codepage: int, pid: int):
    if off + 4 > len(data):
        return None
    vtype = struct.unpack_from("<H", data, off)[0]
    p = off + 4
    base = vtype & 0x0FFF
    try:
        if base == 0x1E:                       # VT_LPSTR
            n = struct.unpack_from("<I", data, p)[0]
            raw = data[p + 4:p + 4 + n].split(b"\x00")[0]
            enc = "utf-8" if codepage in (65001, 1200) else "latin-1"
            return raw.decode(enc, "replace")
        if base == 0x1F:                       # VT_LPWSTR
            n = struct.unpack_from("<I", data, p)[0]
            raw = data[p + 4:p + 4 + n * 2]
            return raw.decode("utf-16-le", "replace").split("\x00")[0]
        if base == 0x40:                       # VT_FILETIME
            v = struct.unpack_from("<Q", data, p)[0]
            if pid == 10:                      # total edit time
                return _duration(v)
            return _filetime(v)
        if base == 0x02:                       # VT_I2
            return struct.unpack_from("<h", data, p)[0]
        if base in (0x03, 0x16):               # VT_I4 / VT_INT
            return struct.unpack_from("<i", data, p)[0]
        if base in (0x13, 0x17):               # VT_UI4 / VT_UINT
            return struct.unpack_from("<I", data, p)[0]
        if base == 0x0B:                       # VT_BOOL
            return struct.unpack_from("<h", data, p)[0] != 0
        if base == 0x48:                       # VT_CLSID
            return _guid(data[p:p + 16])
    except struct.error:
        return None
    return None


def _parse_set(data: bytes, base: int, names: dict) -> dict:
    out: dict = {}
    if base + 8 > len(data):
        return out
    _size, count = struct.unpack_from("<II", data, base)
    codepage = 1252
    idx = []
    for i in range(min(count, 512)):
        p = base + 8 + i * 8
        if p + 8 > len(data):
            break
        pid, poff = struct.unpack_from("<II", data, p)
        idx.append((pid, base + poff))
    for pid, poff in idx:
        if pid == 1:                            # codepage
            cp = _read_value(data, poff, 1252, pid)
            if isinstance(cp, int) and cp:
                codepage = cp & 0xFFFF
    for pid, poff in idx:
        if pid in (0, 1):
            continue
        val = _read_value(data, poff, codepage, pid)
        if val is None or val == "":
            continue
        out[names.get(pid, f"pid_{pid}")] = val
    return out


def parse_property_stream(data: bytes) -> dict:
    """Return {field: value} merged from every property set in the stream."""
    if len(data) < 0x30 or data[:2] != b"\xfe\xff":
        return {}
    nsets = struct.unpack_from("<I", data, 0x18)[0]
    merged: dict = {}
    for i in range(min(nsets, 4)):
        p = 0x1C + i * 20
        if p + 20 > len(data):
            break
        fmtid = _guid(data[p:p + 16])
        off = struct.unpack_from("<I", data, p + 16)[0]
        if fmtid == _FMTID_SUMMARY:
            merged.update(_parse_set(data, off, _SUMMARY))
        elif fmtid == _FMTID_DOCSUMMARY:
            merged.update(_parse_set(data, off, _DOCSUMMARY))
        else:
            merged.update(_parse_set(data, off, {}))
    return merged
