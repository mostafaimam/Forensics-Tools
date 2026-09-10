"""Top-level ESE database object."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from windows_bits.esedb import coltypes as _ct
from windows_bits.esedb.btree import walk_leaves, walk_leaves_via_siblings
from windows_bits.esedb.catalog import load_catalog
from windows_bits.esedb.longvalue import LongValueStore
from windows_bits.esedb.pages import DbHeader, EseError, Pager, parse_header
from windows_bits.esedb.records import TaggedValue, parse_record, sevenbit_decompress

__all__ = ["EseDatabase", "EseError"]


@dataclass
class TableInfo:
    name: str
    row_estimate: int
    columns: list      # (name, type_name)


class EseTable:
    def __init__(self, db: "EseDatabase", meta):
        self._db = db
        self.meta = meta
        self.name = meta.name
        self.columns = meta.columns
        self._fixed = [(c.id, _ct.FIXED_SIZE.get(c.coltype, c.size))
                       for c in meta.columns if c.is_fixed]
        self._fixed.sort()
        self._var = [(c.id, c.size) for c in meta.columns if c.is_variable]
        self._var.sort()
        self._by_id = {c.id: c for c in meta.columns}
        self._lv = None

    def column_by_id(self, cid: int):
        return self._by_id.get(cid)

    def column_by_name(self, name: str):
        for c in self.columns:
            if c.name == name:
                return c
        return None

    @property
    def lv(self):
        if self._lv is None:
            self._lv = LongValueStore(self._db.pager, self.meta.lv_fdp_page)
        return self._lv

    def _value(self, col, raw):
        if isinstance(raw, TaggedValue):
            if raw.is_separated_lv and len(raw.raw) >= 4:
                lid = struct.unpack("<I", raw.raw[:4])[0]
                data = self.lv.get(lid)
            else:
                data = raw.raw
            if raw.is_compressed or (data[:1] == b"\x18"):
                data = sevenbit_decompress(data)
            return _ct.decode(col.coltype, data, col.code_page)
        return _ct.decode(col.coltype, raw, col.code_page)

    def records(self):
        pager = self._db.pager
        leaves = walk_leaves(pager, self.meta.fdp_page)
        got_any = False
        for leaf in leaves:
            got_any = True
            yield self._decode(leaf.data)
        if not got_any:
            for leaf in walk_leaves_via_siblings(pager, self.meta.fdp_page):
                yield self._decode(leaf.data)

    def _decode(self, data: bytes) -> dict:
        raw = parse_record(data, self._fixed, self._var,
                           new_tagged=self._db.new_tagged)
        row: dict = {}
        for cid, rawval in raw.items():
            col = self._by_id.get(cid)
            if col is None:
                continue
            try:
                row[col.name] = self._value(col, rawval)
            except Exception:                    # noqa: BLE001
                row[col.name] = rawval if isinstance(rawval, bytes) else None
        for c in self.columns:
            row.setdefault(c.name, None)
        return row


class EseDatabase:
    def __init__(self, data: bytes):
        self.data = data
        self.header: DbHeader = parse_header(data)
        self.pager = Pager(data, self.header)
        self.new_tagged = self.header.format_revision >= 0x11
        self._catalog = load_catalog(self.pager, self.new_tagged)

    @classmethod
    def from_file(cls, path) -> "EseDatabase":
        from pathlib import Path
        return cls(Path(path).read_bytes())

    @property
    def table_names(self) -> list[str]:
        return sorted(n for n in self._catalog
                      if not n.startswith("MSys"))

    def all_table_names(self) -> list[str]:
        return sorted(self._catalog)

    def table(self, name: str) -> EseTable:
        meta = self._catalog.get(name)
        if meta is None:
            raise EseError(f"no such table: {name}")
        return EseTable(self, meta)

    def info(self) -> dict:
        return {
            "format_version": hex(self.header.format_version),
            "format_revision": hex(self.header.format_revision),
            "page_size": self.header.page_size,
            "state": self.header.state,
            "clean": self.header.state == 1,
            "tables": len(self._catalog),
        }
