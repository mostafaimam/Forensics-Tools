"""Parse MSysObjects (the ESE catalog) into tables and columns."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from windows_esedb import coltypes as _ct
from windows_esedb.btree import walk_leaves, walk_leaves_via_siblings
from windows_esedb.records import parse_record

CATALOG_FDP_PAGE = 4
CATALOG_OBJID = 2

# type values in MSysObjects.Type
TYPE_TABLE = 1
TYPE_COLUMN = 2
TYPE_INDEX = 3
TYPE_LONG_VALUE = 4

# the catalog's own (fixed) column layout - (id, byte length)
_CATALOG_FIXED = [
    (1, 4),   # ObjidTable
    (2, 2),   # Type
    (3, 4),   # Id
    (4, 4),   # ColtypOrPgnoFDP
    (5, 4),   # SpaceUsage
    (6, 4),   # Flags
    (7, 4),   # PagesOrLocale
    (8, 1),   # RootFlag
    (9, 2),   # RecordOffset
    (10, 4),  # LCMapFlags
    (11, 2),  # KeyMost
]
_CATALOG_VAR = [(128, 0)]     # Name


@dataclass
class Column:
    id: int
    name: str
    coltype: int
    size: int
    code_page: int = 1200
    flags: int = 0

    @property
    def is_fixed(self) -> bool:
        return self.id <= 127 and self.coltype not in _ct.LONG_TYPES \
            and self.coltype in _ct.FIXED_SIZE

    @property
    def is_variable(self) -> bool:
        return 128 <= self.id <= 255 and self.coltype not in _ct.LONG_TYPES

    @property
    def is_tagged(self) -> bool:
        return self.id >= 256 or self.coltype in _ct.LONG_TYPES \
            or (not self.is_fixed and not self.is_variable)


@dataclass
class Table:
    name: str
    objid: int
    fdp_page: int
    lv_fdp_page: int = 0
    columns: list = field(default_factory=list)      # Column

    def column_by_id(self, cid: int):
        for c in self.columns:
            if c.id == cid:
                return c
        return None


def _i(v):
    if isinstance(v, (bytes, bytearray)):
        return struct.unpack("<i", v[:4].ljust(4, b"\0"))[0]
    return int(v or 0)


def _h(v):
    if isinstance(v, (bytes, bytearray)):
        return struct.unpack("<h", v[:2].ljust(2, b"\0"))[0]
    return int(v or 0)


def load_catalog(pager, new_tagged: bool) -> dict[str, Table]:
    rows = list(walk_leaves(pager, CATALOG_FDP_PAGE))
    if not rows:
        rows = list(walk_leaves_via_siblings(pager, CATALOG_FDP_PAGE))

    tables_by_objid: dict[int, Table] = {}
    pending_cols: list[tuple] = []
    pending_lv: list[tuple] = []

    for leaf in rows:
        rec = parse_record(leaf.data, _CATALOG_FIXED, _CATALOG_VAR,
                           new_tagged=new_tagged)
        objid_table = _i(rec.get(1))
        rtype = _h(rec.get(2))
        rid = _i(rec.get(3))
        coltyp_or_fdp = _i(rec.get(4))
        space = _i(rec.get(5))
        flags = _i(rec.get(6))
        pages_or_locale = _i(rec.get(7))
        name_raw = rec.get(128)
        name = ""
        if isinstance(name_raw, (bytes, bytearray)):
            name = name_raw.decode("utf-16-le", "replace").rstrip("\x00") \
                or name_raw.decode("cp1252", "replace").rstrip("\x00")

        if rtype == TYPE_TABLE:
            tables_by_objid[rid] = Table(name=name, objid=rid,
                                         fdp_page=coltyp_or_fdp)
        elif rtype == TYPE_COLUMN:
            pending_cols.append((objid_table, Column(
                id=rid, name=name, coltype=coltyp_or_fdp, size=space,
                code_page=pages_or_locale or 1200, flags=flags)))
        elif rtype == TYPE_LONG_VALUE:
            pending_lv.append((objid_table, coltyp_or_fdp))

    for objid_table, col in pending_cols:
        t = tables_by_objid.get(objid_table)
        if t is not None:
            t.columns.append(col)
    for objid_table, lv_fdp in pending_lv:
        t = tables_by_objid.get(objid_table)
        if t is not None:
            t.lv_fdp_page = lv_fdp

    for t in tables_by_objid.values():
        t.columns.sort(key=lambda c: c.id)

    return {t.name: t for t in tables_by_objid.values() if t.name}
