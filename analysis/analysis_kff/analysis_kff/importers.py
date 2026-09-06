"""Parsers for the common hash-set distribution formats."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from pathlib import Path

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_LEN_ALGO = {32: "md5", 40: "sha1", 64: "sha256"}


def detect_format(path: Path) -> str:
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix in (".db", ".sqlite", ".sqlite3"):
        return "nsrl-sqlite"
    try:
        with p.open("rb") as fh:
            head = fh.read(16)
        if head[:16] == b"SQLite format 3\x00":
            return "nsrl-sqlite"
    except OSError:
        pass
    if suffix == ".json":
        return "projectvic"
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
    except OSError:
        first = ""
    low = first.lower()
    if "sha-1" in low and "md5" in low and "crc32" in low:
        return "nsrl-text"
    if first.lstrip().startswith(("{", "[")):
        return "projectvic"
    if "md5" in low or "sha1" in low or "sha256" in low or "hashset" in low:
        return "csv"
    return "lines"


def parse(path: str, fmt: str = "auto"):
    p = Path(path)
    if fmt == "auto":
        fmt = detect_format(p)
    fn = {"nsrl-text": _nsrl_text, "nsrl-sqlite": _nsrl_sqlite,
          "projectvic": _projectvic, "csv": _csv_any, "lines": _lines,
          "hashkeeper": _csv_any}.get(fmt)
    if fn is None:
        raise ValueError(f"unknown format: {fmt}")
    yield from fn(p)
    return


def _nsrl_text(p: Path):
    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if not header:
            return
        idx = {name.strip().strip('"').lower(): i
               for i, name in enumerate(header)}
        i_sha1 = idx.get("sha-1", idx.get("sha1"))
        i_md5 = idx.get("md5")
        i_sha256 = idx.get("sha-256", idx.get("sha256"))
        i_name = idx.get("filename", idx.get("file_name"))
        i_size = idx.get("filesize", idx.get("file_size"))
        for row in reader:
            if not row:
                continue
            rec = {}
            if i_sha1 is not None and i_sha1 < len(row):
                rec["sha1"] = row[i_sha1].strip().strip('"')
            if i_md5 is not None and i_md5 < len(row):
                rec["md5"] = row[i_md5].strip().strip('"')
            if i_sha256 is not None and i_sha256 < len(row):
                rec["sha256"] = row[i_sha256].strip().strip('"')
            if i_name is not None and i_name < len(row):
                rec["name"] = row[i_name].strip().strip('"')
            if i_size is not None and i_size < len(row):
                rec["size"] = row[i_size].strip().strip('"')
            if any(rec.get(a) for a in ("md5", "sha1", "sha256")):
                yield rec


def _nsrl_sqlite(p: Path):
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        tables = {r[0].lower() for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        target = None
        for cand in ("file", "files", "nsrlfile", "hashes", "hashset"):
            if cand in tables:
                target = cand
                break
        if target is None:
            raise ValueError(f"no recognised hash table in {p.name} "
                             f"(has: {sorted(tables)})")
        cols = {r[1].lower(): r[1] for r in con.execute(
            f'PRAGMA table_info("{target}")')}
        cmap = {}
        for algo, names in (("md5", ("md5",)), ("sha1", ("sha1", "sha-1")),
                            ("sha256", ("sha256", "sha-256"))):
            for nm in names:
                if nm in cols:
                    cmap[algo] = cols[nm]
                    break
        if not cmap:
            raise ValueError(f"no hash columns in table {target}")
        sel = ", ".join(f'"{c}"' for c in cmap.values())
        for row in con.execute(f'SELECT {sel} FROM "{target}"'):
            yield {algo: val for algo, val in zip(cmap.keys(), row) if val}
    finally:
        con.close()


def _projectvic(p: Path):
    data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    items = data
    if isinstance(data, dict):
        items = (data.get("value") or data.get("odata.value")
                 or data.get("media") or data.get("Files") or [])
    for item in items:
        if not isinstance(item, dict):
            continue
        files = item.get("files") or item.get("Files") or [item]
        for f in files:
            if not isinstance(f, dict):
                continue
            rec = {}
            for key, algo in (("MD5", "md5"), ("md5", "md5"),
                              ("SHA1", "sha1"), ("sha1", "sha1"),
                              ("SHA256", "sha256"), ("sha256", "sha256")):
                if f.get(key):
                    rec[algo] = str(f[key])
            if rec:
                yield rec


def _csv_any(p: Path):
    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(fh, dialect)
        rows = iter(reader)
        first = next(rows, None)
        if first is None:
            return
        header_map = {}
        looks_header = any(not _HEX.match(c.strip()) for c in first)
        if looks_header:
            for i, name in enumerate(first):
                key = name.strip().lower().replace("-", "").replace("_", "")
                if key in ("md5", "sha1", "sha256"):
                    header_map[key] = i
        else:
            rows = iter([first] + list(rows))
        for row in rows:
            rec = {}
            if header_map:
                for algo, i in header_map.items():
                    if i < len(row) and _HEX.match(row[i].strip()):
                        rec[algo] = row[i].strip()
            else:
                for cell in row:
                    c = cell.strip().strip('"')
                    if _HEX.match(c) and len(c) in _LEN_ALGO:
                        rec[_LEN_ALGO[len(c)]] = c
            if rec:
                yield rec


def _lines(p: Path):
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            token = re.split(r"[\s,;|]", line, maxsplit=1)[0]
            if ":" in token:
                algo, _, val = token.partition(":")
                algo = algo.strip().lower().replace("-", "")
                if algo in ("md5", "sha1", "sha256") and _HEX.match(val):
                    yield {algo: val}
                    continue
                token = val
            if _HEX.match(token) and len(token) in _LEN_ALGO:
                yield {_LEN_ALGO[len(token)]: token}
