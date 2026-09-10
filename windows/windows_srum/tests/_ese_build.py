"""A small, general ESE database writer for the artefact-tool test-suites.

Legacy format (revision 0x0C), 4 KiB pages, one root+leaf page per table.
Not a faithful ESE writer in every corner - just enough that the vendored
``windows_esedb`` reader round-trips catalog + records.
"""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

PAGE = 4096
MAGIC = 0x89ABCDEF
FLAG_ROOT = 0x0001
FLAG_LEAF = 0x0002

# column types
LONG = 4
UNSIGNED_LONG = 14
DATE_TIME = 8
BINARY = 9
LONG_BINARY = 11
TEXT = 10
LONG_TEXT = 12
LONG_LONG = 15
GUID = 16

_FIXED_SIZE = {LONG: 4, UNSIGNED_LONG: 4, DATE_TIME: 8, LONG_LONG: 8, GUID: 16}
_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def ole_days(dt: datetime) -> float:
    return (dt - _OLE_EPOCH).total_seconds() / 86400.0


def _enc(coltype: int, value) -> bytes:
    if value is None:
        return b""
    if coltype in (LONG,):
        return struct.pack("<i", int(value))
    if coltype == UNSIGNED_LONG:
        return struct.pack("<I", int(value))
    if coltype == LONG_LONG:
        return struct.pack("<q", int(value))
    if coltype == DATE_TIME:
        v = ole_days(value) if isinstance(value, datetime) else float(value)
        return struct.pack("<d", v)
    if coltype == GUID:
        return uuid.UUID(str(value)).bytes_le
    if coltype in (TEXT, LONG_TEXT):
        return str(value).encode("utf-16-le")
    if coltype in (BINARY, LONG_BINARY):
        return bytes(value)
    raise ValueError(coltype)


class Column:
    def __init__(self, cid: int, name: str, coltype: int, size: int = 0):
        self.id = cid
        self.name = name
        self.coltype = coltype
        self.size = size or _FIXED_SIZE.get(coltype, 0)

    @property
    def is_fixed(self) -> bool:
        return self.id <= 127 and self.coltype in _FIXED_SIZE

    @property
    def is_variable(self) -> bool:
        return 128 <= self.id <= 255 and self.coltype not in (LONG_TEXT,
                                                              LONG_BINARY)

    @property
    def is_tagged(self) -> bool:
        return not self.is_fixed and not self.is_variable


class Table:
    def __init__(self, name: str, objid: int, fdp: int, columns, rows,
                 lv_fdp: int = 0):
        self.name = name
        self.objid = objid
        self.fdp = fdp
        self.columns = columns
        self.rows = rows
        self.lv_fdp = lv_fdp


def _data_definition(fixed, variable, tagged) -> bytes:
    fixed = sorted(fixed)
    variable = sorted(variable)
    tagged = sorted(tagged)
    last_fixed = fixed[-1][0] if fixed else 0
    last_var = variable[-1][0] if variable else 0

    fixed_blob = b"".join(v for _, v in fixed)
    nbitmap = (last_fixed + 7) // 8
    bitmap = bytearray(nbitmap)
    present = {cid for cid, _ in fixed}
    for cid in range(1, last_fixed + 1):
        if cid not in present:
            bitmap[(cid - 1) // 8] |= 1 << ((cid - 1) % 8)

    var_size_off = 4 + len(fixed_blob) + nbitmap
    n_var = (last_var - 127) if last_var >= 128 else 0
    var_map = dict(variable)
    var_arr = bytearray()
    var_data = bytearray()
    running = 0
    for i in range(n_var):
        cid = 128 + i
        if cid in var_map:
            var_data += var_map[cid]
            running += len(var_map[cid])
            var_arr += struct.pack("<H", running & 0x7FFF)
        else:
            var_arr += struct.pack("<H", (running & 0x7FFF) | 0x8000)

    out = bytearray()
    out += struct.pack("<BBH", last_fixed, last_var if n_var else 0,
                       var_size_off)
    out += fixed_blob
    out += bytes(bitmap)
    out += bytes(var_arr)
    out += bytes(var_data)

    if tagged:
        entry_arr = bytearray()
        tag_data = bytearray()
        base = len(tagged) * 4
        for cid, val in tagged:
            entry_arr += struct.pack("<HH", cid, base + len(tag_data))
            tag_data += val
        out += bytes(entry_arr) + bytes(tag_data)
    return bytes(out)


def _row_record(columns, values: dict) -> bytes:
    fixed, variable, tagged = [], [], []
    for c in columns:
        if c.name not in values or values[c.name] is None:
            continue
        raw = _enc(c.coltype, values[c.name])
        if not raw:
            continue
        if c.is_fixed:
            fixed.append((c.id, raw))
        elif c.is_variable:
            variable.append((c.id, raw))
        else:
            tagged.append((c.id, raw))
    return _data_definition(fixed, variable, tagged)


def _page(number, flags, father, tag_datas) -> bytes:
    p = bytearray(PAGE)
    struct.pack_into("<I", p, 0x18, father)
    struct.pack_into("<H", p, 0x22, len(tag_datas))
    struct.pack_into("<I", p, 0x24, flags)
    cur = 0x28
    tags = []
    for d in tag_datas:
        rel = cur - 0x28
        p[cur:cur + len(d)] = d
        tags.append((len(d), rel))
        cur += len(d)
        if cur % 4:
            cur += 4 - (cur % 4)
    for i, (size, off) in enumerate(tags):
        struct.pack_into("<HH", p, PAGE - (i + 1) * 4,
                         size & 0x1FFF, off & 0x1FFF)
    return bytes(p)


def _leaf_entry(key: bytes, data: bytes) -> bytes:
    return struct.pack("<H", len(key)) + key + data


_CAT_FIXED = [(1, 4), (2, 2), (3, 4), (4, 4), (5, 4), (6, 4), (7, 4),
              (8, 1), (9, 2), (10, 4), (11, 2)]


def _cat_row(objid_table, rtype, rid, coltyp_or_fdp, space, codepage, name):
    fixed = [(1, struct.pack("<i", objid_table)),
             (2, struct.pack("<h", rtype)),
             (3, struct.pack("<i", rid)),
             (4, struct.pack("<i", coltyp_or_fdp)),
             (5, struct.pack("<i", space)),
             (6, struct.pack("<i", 0)),
             (7, struct.pack("<i", codepage)),
             (8, b"\x00"), (9, struct.pack("<h", 0)),
             (10, struct.pack("<i", 0)), (11, struct.pack("<H", 0))]
    variable = [(128, name.encode("utf-16-le"))] if name else []
    return _data_definition(fixed, variable, [])


def build(tables) -> bytes:
    """tables: list[Table].  Table.fdp pages must be >= 4 and unique."""
    cat_entries = [b""]
    n = 0
    for t in tables:
        n += 1
        cat_entries.append(_leaf_entry(struct.pack("<H", n),
                           _cat_row(0, 1, t.objid, t.fdp, 0, 0, t.name)))
        for c in t.columns:
            n += 1
            cat_entries.append(_leaf_entry(struct.pack("<H", n),
                               _cat_row(t.objid, 2, c.id, c.coltype, c.size,
                                        1200, c.name)))
        if t.lv_fdp:
            n += 1
            cat_entries.append(_leaf_entry(struct.pack("<H", n),
                               _cat_row(t.objid, 4, 0x7FFFFFFF, t.lv_fdp, 0,
                                        0, "")))

    pages = {4: _page(4, FLAG_ROOT | FLAG_LEAF, 4, cat_entries)}
    for i, t in enumerate(tables):
        entries = [b""]
        for k, values in enumerate(t.rows, 1):
            entries.append(_leaf_entry(struct.pack("<i", k),
                                       _row_record(t.columns, values)))
        pages[t.fdp] = _page(t.fdp, FLAG_ROOT | FLAG_LEAF, t.fdp, entries)
        if t.lv_fdp:
            pages[t.lv_fdp] = _page(t.lv_fdp, FLAG_ROOT | FLAG_LEAF,
                                    t.lv_fdp, [b""])

    hdr = bytearray(PAGE)
    struct.pack_into("<I", hdr, 4, MAGIC)
    struct.pack_into("<I", hdr, 8, 0x620)
    struct.pack_into("<I", hdr, 12, 0)
    struct.pack_into("<I", hdr, 0x34, 1)
    struct.pack_into("<I", hdr, 0xE8, 0x0C)
    struct.pack_into("<I", hdr, 0xEC, PAGE)
    body = bytearray()
    for pnum in range(1, max(pages) + 1):
        body += pages.get(pnum, bytes(PAGE))
    return bytes(hdr) + bytes(hdr) + bytes(body)
