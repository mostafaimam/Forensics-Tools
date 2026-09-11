"""Apply maps to discovered databases; fall back to a schema recon."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from windows_sqlmap import dbopen
from windows_sqlmap.timeconv import convert


@dataclass
class MapHit:
    db: str
    map_name: str
    description: str
    map_source: str
    rows: list = field(default_factory=list)
    error: str = ""


@dataclass
class ReconResult:
    db: str
    tables: list = field(default_factory=list)   # (name, row_count)
    matched: bool = False


@dataclass
class Result:
    hits: list = field(default_factory=list)
    recon: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    dbs_seen: int = 0


def _tables(con: sqlite3.Connection) -> list[str]:
    cur = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")
    return [r[0] for r in cur.fetchall()]


def _row_count(con, table) -> int:
    try:
        return con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    except sqlite3.Error:
        return -1


def process(db_path: str, maps, *, dump_table=None, row_limit=50000):
    """Run every applicable map against one database."""
    hits: list[MapHit] = []
    recon = None
    try:
        with dbopen.connect(db_path) as con:
            tables = set(_tables(con))
            matched_any = False
            for m in maps:
                if not m.matches(tables):
                    continue
                matched_any = True
                hit = MapHit(db=db_path, map_name=m.name,
                            description=m.description, map_source=m.source)
                try:
                    cur = con.execute(m.query)
                    cols = [c[0] for c in cur.description]
                    for i, row in enumerate(cur):
                        if i >= row_limit:
                            break
                        rec = dict(zip(cols, row))
                        out = {}
                        for j, cname in enumerate(m.columns):
                            src = cols[j] if j < len(cols) else None
                            out[cname] = rec.get(src, "") if src else ""
                        if m.time_col and m.time_col in out:
                            out[m.time_col] = convert(out[m.time_col],
                                                      m.time_format)
                        hit.rows.append(out)
                except sqlite3.Error as e:
                    hit.error = str(e)
                hits.append(hit)
            if not matched_any:
                tinfo = [(t, _row_count(con, t)) for t in sorted(tables)]
                recon = ReconResult(db=db_path, tables=tinfo, matched=False)
            if dump_table and dump_table in tables:
                cur = con.execute(f'SELECT * FROM "{dump_table}" '
                                  f'LIMIT {row_limit}')
                cols = [c[0] for c in cur.description]
                hit = MapHit(db=db_path, map_name=f"dump:{dump_table}",
                            description="raw table dump", map_source="--dump")
                hit.rows = [dict(zip(cols, r)) for r in cur.fetchall()]
                hits.append(hit)
    except sqlite3.Error as e:
        return hits, recon, str(e)
    return hits, recon, ""


def scan(db_paths, maps, *, dump_table=None) -> Result:
    res = Result()
    for p in db_paths:
        res.dbs_seen += 1
        hits, recon, err = process(str(p), maps, dump_table=dump_table)
        res.hits.extend(hits)
        if recon:
            res.recon.append(recon)
        if err:
            res.errors.append(f"{p}: {err}")
    return res
