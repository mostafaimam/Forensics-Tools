"""The local KFF hash index (SQLite)."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

CATEGORIES = ("known-good", "known-bad", "notable")
_PRECEDENCE = {"known-bad": 3, "notable": 2, "known-good": 1}
_ALGOS = ("md5", "sha1", "sha256")


def default_db() -> Path:
    env = os.environ.get("ANALYSIS_KFF_DB")
    if env:
        return Path(env)
    return Path.home() / ".local/share/analysis_kff/kff.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sets (
    id            INTEGER PRIMARY KEY,
    name          TEXT UNIQUE NOT NULL,
    category      TEXT NOT NULL,
    source_path   TEXT,
    source_format TEXT,
    imported_utc  TEXT,
    hash_count    INTEGER DEFAULT 0,
    note          TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hash (
    algo    TEXT NOT NULL,
    value   TEXT NOT NULL,
    set_id  INTEGER NOT NULL REFERENCES sets(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_hash_lookup ON hash(algo, value);
CREATE INDEX IF NOT EXISTS ix_hash_set ON hash(set_id);
"""


class KFFStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_db()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(_SCHEMA)

    # -- sets ------------------------------------------------------
    def create_set(self, name: str, category: str, source_path: str = "",
                   source_format: str = "", note: str = "") -> int:
        if category not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES}")
        cur = self.db.execute(
            "INSERT INTO sets(name,category,source_path,source_format,"
            "imported_utc,note) VALUES(?,?,?,?,?,?)",
            (name, category, source_path, source_format,
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), note))
        self.db.commit()
        return cur.lastrowid

    def set_id(self, name: str) -> int | None:
        row = self.db.execute("SELECT id FROM sets WHERE name=?",
                              (name,)).fetchone()
        return row[0] if row else None

    def list_sets(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT name,category,source_format,imported_utc,hash_count,note,"
            "source_path FROM sets ORDER BY category,name").fetchall()
        return [dict(zip(("name", "category", "format", "imported_utc",
                          "hashes", "note", "source"), r)) for r in rows]

    def remove_set(self, name: str) -> bool:
        sid = self.set_id(name)
        if sid is None:
            return False
        self.db.execute("DELETE FROM hash WHERE set_id=?", (sid,))
        self.db.execute("DELETE FROM sets WHERE id=?", (sid,))
        self.db.commit()
        return True

    # -- bulk import --------------------------------------------
    def import_records(self, set_id: int, records, *, batch: int = 50_000,
                       progress=None) -> int:
        """*records* yields dicts with any of md5/sha1/sha256 (hex str)."""
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("PRAGMA journal_mode=MEMORY")
        n = 0
        buf: list[tuple] = []
        seen_none = True
        for rec in records:
            for algo in _ALGOS:
                v = rec.get(algo)
                if v:
                    buf.append((algo, v.strip().lower(), set_id))
                    seen_none = False
            if len(buf) >= batch:
                self.db.executemany(
                    "INSERT INTO hash(algo,value,set_id) VALUES(?,?,?)", buf)
                n += len(buf)
                buf.clear()
                if progress:
                    progress(n)
        if buf:
            self.db.executemany(
                "INSERT INTO hash(algo,value,set_id) VALUES(?,?,?)", buf)
            n += len(buf)
        self.db.execute("UPDATE sets SET hash_count=hash_count+? WHERE id=?",
                        (n, set_id))
        self.db.commit()
        self.db.execute("PRAGMA synchronous=NORMAL")
        if seen_none and n == 0:
            raise ValueError("no md5/sha1/sha256 values found in the source")
        return n

    # -- lookup ------------------------------------------------
    def classify(self, hashes: dict) -> dict:
        """hashes = {algo: hexvalue}.  Returns the strongest match."""
        best = None
        for algo, value in hashes.items():
            if not value or algo not in _ALGOS:
                continue
            for cat, name in self.db.execute(
                    "SELECT s.category, s.name FROM hash h "
                    "JOIN sets s ON h.set_id=s.id "
                    "WHERE h.algo=? AND h.value=?",
                    (algo, value.strip().lower())):
                if best is None or _PRECEDENCE[cat] > _PRECEDENCE[best[0]]:
                    best = (cat, name, algo)
        if best is None:
            return {"status": "unknown", "set": "", "matched_algo": ""}
        return {"status": best[0], "set": best[1], "matched_algo": best[2]}

    def stats(self) -> dict:
        total = self.db.execute("SELECT COUNT(*) FROM hash").fetchone()[0]
        by_cat = dict(self.db.execute(
            "SELECT s.category, COUNT(*) FROM hash h JOIN sets s "
            "ON h.set_id=s.id GROUP BY s.category").fetchall())
        return {"db": str(self.path), "sets": len(self.list_sets()),
                "hashes": total, "by_category": by_cat}

    def close(self) -> None:
        self.db.close()
