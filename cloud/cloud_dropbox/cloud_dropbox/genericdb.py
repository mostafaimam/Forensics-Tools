"""Generic, schema-agnostic SQLite table dump.

Used when a vendor's local database format is proprietary and
undocumented: rather than guess at column semantics, every table is
read in full and each row is preserved as a JSON blob, with only
conservative, name-based hints (a column literally named something
like ``path`` or ``time``) surfaced separately.
"""

from __future__ import annotations

import json
import sqlite3

from cloud_dropbox.dbopen import connect

_PATH_HINTS = ("path", "name", "file", "folder", "url")
_TIME_HINTS = ("time", "date", "modified", "created", "utc")
_SIZE_HINTS = ("size", "bytes", "length")

SQLITE_MAGIC = b"SQLite format 3\x00"


def is_sqlite(path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def list_tables(con: sqlite3.Connection) -> list[str]:
    try:
        return [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'")]
    except sqlite3.Error:
        return []


def _hint(col: str, hints: tuple) -> bool:
    low = col.lower()
    return any(h in low for h in hints)


def dump_table(con: sqlite3.Connection, table: str) -> tuple[list[str],
                                                             list[dict]]:
    try:
        cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
    except sqlite3.Error:
        return [], []
    if not cols:
        return [], []
    try:
        cur = con.execute(f'SELECT * FROM "{table}"')
    except sqlite3.Error:
        return cols, []
    rows = []
    for r in cur:
        d = dict(zip(cols, r))
        rows.append(d)
    return cols, rows


def dump_all_tables(db_path: str) -> dict:
    """Return {table_name: (columns, rows)} for every user table."""
    out = {}
    with connect(db_path) as con:
        for table in list_tables(con):
            cols, rows = dump_table(con, table)
            out[table] = (cols, rows)
    return out


def shape_rows(source: str, table: str, cols: list[str], rows: list[dict]
              ) -> list[dict]:
    path_col = next((c for c in cols if _hint(c, _PATH_HINTS)), "")
    time_col = next((c for c in cols if _hint(c, _TIME_HINTS)), "")
    size_col = next((c for c in cols if _hint(c, _SIZE_HINTS)), "")
    out = []
    for r in rows:
        out.append({
            "source": source, "table": table,
            "path_hint": str(r.get(path_col, "")) if path_col else "",
            "time_hint": str(r.get(time_col, "")) if time_col else "",
            "size_hint": str(r.get(size_col, "")) if size_col else "",
            "row_json": json.dumps(r, default=str),
        })
    return out
