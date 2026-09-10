"""Hand-build a minimal, well-formed ESE database for the test-suite.

Legacy format (revision 0x0C, so the non-extended tagged layout), 4 KiB
pages, one hive bin of pages.  Enough to exercise the header, the catalog,
the B-tree walk and the fixed / variable / tagged record layout.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

PAGE = 4096
MAGIC = 0x89ABCDEF

# column types
LONG = 4
DATE_TIME = 8
TEXT = 10
LONG_TEXT = 12
LONG_LONG = 15

FLAG_ROOT = 0x0001
FLAG_LEAF = 0x0002

_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def ole_days(dt: datetime) -> float:
    return (dt - _OLE_EPOCH).total_seconds() / 86400.0


def _page(number: int, flags: int, father: int, tag_datas: list[bytes],
          *, prev=0, nxt=0) -> bytes:
    p = bytearray(PAGE)
    struct.pack_into("<i", p, 0x10, prev)
    struct.pack_into("<i", p, 0x14, nxt)
    struct.pack_into("<I", p, 0x18, father)
    struct.pack_into("<H", p, 0x22, len(tag_datas))
    struct.pack_into("<I", p, 0x24, flags)
    # lay tag data forward from 0x28 (right after the 40-byte header)
    cur = 0x28
    data_area_base = 0x28
    tags = []
    for d in tag_datas:
        rel = cur - data_area_base
        p[cur:cur + len(d)] = d
        tags.append((len(d), rel))
        cur += len(d)
        if cur % 4:
            cur += 4 - (cur % 4)
    # tag array grows backward from end of page
    for i, (size, off) in enumerate(tags):
        pos = PAGE - (i + 1) * 4
        struct.pack_into("<HH", p, pos, size & 0x1FFF, off & 0x1FFF)
    return bytes(p)


def _leaf_entry(key: bytes, data: bytes) -> bytes:
    return struct.pack("<H", len(key)) + key + data


def _branch_entry(key: bytes, child: int) -> bytes:
    return struct.pack("<H", len(key)) + key + struct.pack("<I", child)


def data_definition(fixed: list[tuple[int, bytes]],
                    variable: list[tuple[int, bytes]],
                    tagged: list[tuple[int, bytes]]) -> bytes:
    fixed = sorted(fixed)
    variable = sorted(variable)
    tagged = sorted(tagged)
    last_fixed = fixed[-1][0] if fixed else 0
    last_var = variable[-1][0] if variable else 0

    fixed_blob = b"".join(v for _, v in fixed)
    nbitmap = (last_fixed + 7) // 8
    bitmap = bytearray(nbitmap)
    present_ids = {cid for cid, _ in fixed}
    for cid in range(1, last_fixed + 1):
        if cid not in present_ids:               # mark absent columns NULL
            bitmap[(cid - 1) // 8] |= 1 << ((cid - 1) % 8)

    var_size_off = 4 + len(fixed_blob) + nbitmap
    n_var = (last_var - 127) if last_var >= 128 else 0
    var_arr = bytearray()
    var_data = bytearray()
    running = 0
    var_map = dict(variable)
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
                       var_size_off if n_var else var_size_off)
    out += fixed_blob
    out += bytes(bitmap)
    out += bytes(var_arr)
    out += bytes(var_data)

    if tagged:
        n = len(tagged)
        entry_arr = bytearray()
        tag_data = bytearray()
        base = n * 4
        for cid, val in tagged:
            entry_arr += struct.pack("<HH", cid, (base + len(tag_data)))
            tag_data += val
        out += bytes(entry_arr) + bytes(tag_data)
    return bytes(out)


def build() -> bytes:
    # ---------------------------------------------------------------- catalog
    # table "Events", objid 6, FDP page 6 ; long-value FDP page 7
    cat_rows = []

    def cat_table(objid, name, fdp):
        return data_definition(
            [(1, struct.pack("<i", 0)),      # ObjidTable
             (2, struct.pack("<h", 1)),      # Type = table
             (3, struct.pack("<i", objid)),  # Id
             (4, struct.pack("<i", fdp)),    # ColtypOrPgnoFDP
             (5, struct.pack("<i", 0)), (6, struct.pack("<i", 0)),
             (7, struct.pack("<i", 0)), (8, b"\x00"),
             (9, struct.pack("<h", 0)), (10, struct.pack("<i", 0)),
             (11, struct.pack("<H", 0))],
            [(128, name.encode("utf-16-le"))], [])

    def cat_column(objid_table, colid, name, coltype, size, codepage=1200):
        return data_definition(
            [(1, struct.pack("<i", objid_table)),
             (2, struct.pack("<h", 2)),          # Type = column
             (3, struct.pack("<i", colid)),
             (4, struct.pack("<i", coltype)),
             (5, struct.pack("<i", size)),
             (6, struct.pack("<i", 0)),
             (7, struct.pack("<i", codepage)),
             (8, b"\x00"), (9, struct.pack("<h", 0)),
             (10, struct.pack("<i", 0)), (11, struct.pack("<H", 0))],
            [(128, name.encode("utf-16-le"))], [])

    def cat_lv(objid_table, fdp):
        return data_definition(
            [(1, struct.pack("<i", objid_table)),
             (2, struct.pack("<h", 4)),          # Type = long value
             (3, struct.pack("<i", 0x7FFFFFFF)),
             (4, struct.pack("<i", fdp)),
             (5, struct.pack("<i", 0)), (6, struct.pack("<i", 0)),
             (7, struct.pack("<i", 0)), (8, b"\x00"),
             (9, struct.pack("<h", 0)), (10, struct.pack("<i", 0)),
             (11, struct.pack("<H", 0))], [], [])

    cat_rows.append(_leaf_entry(b"\x01Events", cat_table(6, "Events", 6)))
    cat_rows.append(_leaf_entry(b"\x02", cat_column(6, 1, "Id", LONG, 4)))
    cat_rows.append(_leaf_entry(b"\x03", cat_column(6, 2, "Ts", DATE_TIME, 8)))
    cat_rows.append(_leaf_entry(b"\x04", cat_column(6, 3, "Count", LONG_LONG,
                                                    8)))
    cat_rows.append(_leaf_entry(b"\x05", cat_column(6, 128, "Name", TEXT, 0)))
    cat_rows.append(_leaf_entry(b"\x06", cat_column(6, 256, "Note", LONG_TEXT,
                                                    0)))
    cat_rows.append(_leaf_entry(b"\x07", cat_lv(6, 7)))

    catalog_page = _page(4, FLAG_ROOT | FLAG_LEAF, 4, [b""] + cat_rows)

    # ---------------------------------------------------------------- data
    rows = []
    for i, (name, ts, count, note) in enumerate([
        ("alpha", datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc), 3,
         "first note"),
        ("bravo", datetime(2026, 3, 2, 9, 30, tzinfo=timezone.utc), 40,
         "x" * 400),        # long value -> spills to LV tree? kept inline here
        ("charlie", datetime(2026, 3, 3, 10, 0, tzinfo=timezone.utc), 5, ""),
    ], 1):
        rec = data_definition(
            [(1, struct.pack("<i", i)),
             (2, struct.pack("<d", ole_days(ts))),
             (3, struct.pack("<q", count))],
            [(128, name.encode("utf-16-le"))],
            [(256, note.encode("utf-16-le"))] if note else [])
        rows.append(_leaf_entry(struct.pack("<i", i), rec))
    data_page = _page(6, FLAG_ROOT | FLAG_LEAF, 6, [b""] + rows)
    lv_page = _page(7, FLAG_ROOT | FLAG_LEAF, 7, [b""])

    # ---------------------------------------------------------------- header
    hdr = bytearray(PAGE)
    struct.pack_into("<I", hdr, 4, MAGIC)
    struct.pack_into("<I", hdr, 8, 0x620)         # format version
    struct.pack_into("<I", hdr, 12, 0)            # file type = database
    struct.pack_into("<I", hdr, 0x34, 1)          # state = clean shutdown
    struct.pack_into("<I", hdr, 0xE8, 0x0C)       # format revision (< 0x11)
    struct.pack_into("<I", hdr, 0xEC, PAGE)       # page size
    shadow = bytes(hdr)

    pages = {4: catalog_page, 6: data_page, 7: lv_page}
    max_page = max(pages)
    body = bytearray()
    for n in range(1, max_page + 1):
        body += pages.get(n, bytes(PAGE))
    return bytes(hdr) + shadow + bytes(body)
