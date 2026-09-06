"""The on-disk inverted index (SQLite, no FTS extension needed)."""

from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path

from analysis_index.tokenize import decode_positions, encode_positions

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS docs (
    id        INTEGER PRIMARY KEY,
    path      TEXT UNIQUE NOT NULL,
    size      INTEGER,
    mtime     REAL,
    ext       TEXT,
    kind      TEXT,
    n_tokens  INTEGER,
    indexed_utc TEXT
);
CREATE TABLE IF NOT EXISTS postings (
    term      TEXT NOT NULL,
    doc_id    INTEGER NOT NULL,
    tf        INTEGER NOT NULL,
    positions BLOB NOT NULL,
    PRIMARY KEY (term, doc_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS vocab (term TEXT PRIMARY KEY, df INTEGER NOT NULL);
"""


class Index:
    def __init__(self, directory: str | Path, create: bool = False):
        self.dir = Path(directory)
        if create:
            self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "index.db"
        if not create and not self.path.exists():
            raise FileNotFoundError(f"no index at {self.dir}")
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)

    # -- build -----------------------------------------------------
    def begin_bulk(self) -> None:
        self.db.commit()                       # close any implicit transaction
        self.db.execute("PRAGMA synchronous=OFF")

    def end_bulk(self) -> None:
        self.db.commit()
        self.db.execute("PRAGMA synchronous=NORMAL")

    def has_doc(self, path: str) -> float | None:
        row = self.db.execute("SELECT mtime FROM docs WHERE path=?",
                              (path,)).fetchone()
        return row[0] if row else None

    def delete_doc(self, path: str) -> None:
        row = self.db.execute("SELECT id FROM docs WHERE path=?",
                              (path,)).fetchone()
        if not row:
            return
        did = row[0]
        for (term,) in self.db.execute(
                "SELECT term FROM postings WHERE doc_id=?", (did,)):
            self.db.execute("UPDATE vocab SET df=df-1 WHERE term=?", (term,))
        self.db.execute("DELETE FROM postings WHERE doc_id=?", (did,))
        self.db.execute("DELETE FROM docs WHERE id=?", (did,))
        self.db.execute("DELETE FROM vocab WHERE df<=0")

    def add_doc(self, path: str, size: int, mtime: float, ext: str, kind: str,
                term_positions: dict[str, list[int]]) -> int:
        n_tokens = sum(len(v) for v in term_positions.values())
        cur = self.db.execute(
            "INSERT INTO docs(path,size,mtime,ext,kind,n_tokens,indexed_utc) "
            "VALUES(?,?,?,?,?,?,?)",
            (path, size, mtime, ext, kind, n_tokens,
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        did = cur.lastrowid
        rows = [(t, did, len(ps), encode_positions(sorted(ps)))
                for t, ps in term_positions.items()]
        self.db.executemany(
            "INSERT INTO postings(term,doc_id,tf,positions) VALUES(?,?,?,?)",
            rows)
        self.db.executemany(
            "INSERT INTO vocab(term,df) VALUES(?,1) "
            "ON CONFLICT(term) DO UPDATE SET df=df+1",
            [(t,) for t in term_positions])
        return did

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, value))

    # -- query primitives -------------------------------------
    def doc_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM docs").fetchone()[0]

    def df(self, term: str) -> int:
        row = self.db.execute("SELECT df FROM vocab WHERE term=?",
                              (term,)).fetchone()
        return row[0] if row else 0

    def postings(self, term: str) -> dict[int, list[int]]:
        return {doc_id: decode_positions(blob)
                for doc_id, blob in self.db.execute(
                "SELECT doc_id, positions FROM postings WHERE term=?", (term,))}

    def docs_for_term(self, term: str) -> set[int]:
        return {r[0] for r in self.db.execute(
            "SELECT doc_id FROM postings WHERE term=?", (term,))}

    def tf(self, term: str) -> dict[int, int]:
        return {r[0]: r[1] for r in self.db.execute(
            "SELECT doc_id, tf FROM postings WHERE term=?", (term,))}

    def terms_like(self, pattern: str) -> list[str]:
        """SQL GLOB pattern (``foo*``)."""
        return [r[0] for r in self.db.execute(
            "SELECT term FROM vocab WHERE term GLOB ?", (pattern,))]

    def terms_matching(self, regex: str) -> list[str]:
        rx = re.compile(regex)
        return [r[0] for r in self.db.execute("SELECT term FROM vocab")
                if rx.search(r[0])]

    def all_doc_ids(self) -> set[int]:
        return {r[0] for r in self.db.execute("SELECT id FROM docs")}

    def doc_meta(self, doc_id: int) -> dict:
        row = self.db.execute(
            "SELECT path,size,mtime,ext,kind,n_tokens,indexed_utc "
            "FROM docs WHERE id=?", (doc_id,)).fetchone()
        if not row:
            return {}
        return dict(zip(("path", "size", "mtime", "ext", "kind", "n_tokens",
                         "indexed_utc"), row))

    def list_docs(self):
        for row in self.db.execute(
                "SELECT path,size,ext,kind,n_tokens,indexed_utc FROM docs "
                "ORDER BY path"):
            yield dict(zip(("path", "size", "ext", "kind", "n_tokens",
                            "indexed_utc"), row))

    def stats(self) -> dict:
        d = self.doc_count()
        terms = self.db.execute("SELECT COUNT(*) FROM vocab").fetchone()[0]
        toks = self.db.execute(
            "SELECT COALESCE(SUM(n_tokens),0) FROM docs").fetchone()[0]
        kinds = dict(self.db.execute(
            "SELECT kind, COUNT(*) FROM docs GROUP BY kind"))
        return {"index": str(self.path), "documents": d, "unique_terms": terms,
                "total_tokens": toks, "by_kind": kinds}

    def close(self) -> None:
        self.db.commit()
        self.db.close()
