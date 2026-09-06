"""Hash files (or read precomputed hashes) and classify against the KFF."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

_READ = 1 << 20
_HASH_COLS = {"md5", "sha1", "sha256", "sha-1", "sha-256"}


@dataclass
class Row:
    path: str
    size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    status: str = "unknown"      # known-good | known-bad | notable | unknown | error
    set: str = ""
    matched_algo: str = ""
    error: str = ""

    def hashes(self) -> dict:
        return {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256}


def iter_files(paths, *, recurse=True, follow_symlinks=False):
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            it = p.rglob("*") if recurse else p.glob("*")
            for f in it:
                try:
                    if f.is_file() and (follow_symlinks or not f.is_symlink()):
                        yield f
                except OSError:
                    continue


def hash_file(path: Path, algos=("md5", "sha1", "sha256")) -> Row:
    row = Row(path=str(path))
    d = {a: hashlib.new(a) for a in algos}
    try:
        row.size = path.stat().st_size
        with path.open("rb") as fh:
            while True:
                b = fh.read(_READ)
                if not b:
                    break
                for h in d.values():
                    h.update(b)
    except OSError as e:
        row.error = str(e)
        row.status = "error"
        return row
    for a, h in d.items():
        setattr(row, a, h.hexdigest())
    return row


def scan_paths(store, paths, *, algos=("md5", "sha1", "sha256"), recurse=True,
               follow_symlinks=False, progress=None):
    n = 0
    for f in iter_files(paths, recurse=recurse, follow_symlinks=follow_symlinks):
        row = hash_file(f, algos)
        if row.status != "error":
            _apply(store, row)
        n += 1
        if progress:
            progress(n, str(f))
        yield row


def scan_hash_list(store, path: str):
    """Classify precomputed hashes from a CSV/JSON list or a manifest."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    rows: list[Row] = []
    if text.lstrip().startswith(("{", "[")):
        data = json.loads(text)
        entries = data.get("files", data) if isinstance(data, dict) else data
        if isinstance(entries, dict):
            entries = entries.values()
        for e in entries:
            if not isinstance(e, dict):
                continue
            r = Row(path=str(e.get("path", e.get("name", ""))),
                    size=int(e.get("size", 0) or 0),
                    md5=str(e.get("md5", "")), sha1=str(e.get("sha1", "")),
                    sha256=str(e.get("sha256", "")))
            if any(r.hashes().values()):
                _apply(store, r)
                rows.append(r)
        return rows
    reader = csv.DictReader(text.splitlines())
    lower = {c.lower(): c for c in (reader.fieldnames or [])}
    for d in reader:
        r = Row(path=d.get(lower.get("path", ""), "")
                or d.get(lower.get("file", ""), ""),
                md5=d.get(lower.get("md5", ""), "") or "",
                sha1=(d.get(lower.get("sha1", ""), "")
                      or d.get(lower.get("sha-1", ""), "") or ""),
                sha256=(d.get(lower.get("sha256", ""), "")
                        or d.get(lower.get("sha-256", ""), "") or ""))
        try:
            r.size = int(d.get(lower.get("size", ""), 0) or 0)
        except ValueError:
            r.size = 0
        if any(r.hashes().values()):
            _apply(store, r)
            rows.append(r)
    return rows


def _apply(store, row: Row) -> None:
    res = store.classify(row.hashes())
    row.status = res["status"]
    row.set = res["set"]
    row.matched_algo = res["matched_algo"]


@dataclass
class Summary:
    total: int = 0
    counts: dict = field(default_factory=dict)

    def add(self, status: str) -> None:
        self.total += 1
        self.counts[status] = self.counts.get(status, 0) + 1
