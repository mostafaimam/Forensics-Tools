"""Open a browser SQLite store without modifying the evidence.

The database plus any ``-wal`` / ``-shm`` side files are copied to a scratch
directory first, so SQLite may safely checkpoint the write-ahead log into
*our* copy and we see the most recent entries.  If the copy fails (locked,
partial) the original is opened ``immutable`` and read-only.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def connect(db_path: str | Path):
    src = Path(db_path)
    tmp = Path(tempfile.mkdtemp(prefix="bh_"))
    con = None
    try:
        copied = None
        try:
            copied = tmp / src.name
            shutil.copy2(src, copied)
            for ext in ("-wal", "-shm"):
                side = src.with_name(src.name + ext)
                if side.exists():
                    shutil.copy2(side, tmp / side.name)
            con = sqlite3.connect(f"file:{copied}?mode=ro", uri=True,
                                  timeout=2)
        except (OSError, sqlite3.Error):
            if con is not None:
                con.close()
            con = sqlite3.connect(
                f"file:{src}?mode=ro&immutable=1", uri=True, timeout=2)
        con.row_factory = sqlite3.Row
        yield con
    finally:
        if con is not None:
            con.close()
        shutil.rmtree(tmp, ignore_errors=True)


def table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def has_table(con: sqlite3.Connection, table: str) -> bool:
    try:
        return bool(con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone())
    except sqlite3.Error:
        return False


def query(con: sqlite3.Connection, sql: str, params=()):
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []
