"""Walk, hash (size-collision pre-filter), and group files by content."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

_READ = 1 << 20


@dataclass
class FileRec:
    path: str
    size: int
    digest: str = ""
    group: int = -1
    representative: bool = False
    duplicate_of: str = ""
    status: str = ""          # new | duplicate | baseline-hit (for --against)


@dataclass
class Result:
    files: list = field(default_factory=list)      # list[FileRec]
    groups: dict = field(default_factory=dict)      # digest -> [FileRec]
    scanned: int = 0
    hashed: int = 0
    unique: int = 0
    reclaimable: int = 0


def iter_files(paths, *, recurse=True, follow_symlinks=False, exclude=()):
    for raw in paths:
        p = Path(raw)
        cands = [p] if p.is_file() else (
            p.rglob("*") if recurse else p.glob("*")) if p.is_dir() else []
        for f in cands:
            try:
                if not f.is_file() or (not follow_symlinks and f.is_symlink()):
                    continue
            except OSError:
                continue
            s = str(f)
            if any(fnmatch.fnmatch(s, g) or fnmatch.fnmatch(f.name, g)
                   for g in exclude):
                continue
            yield f


def hash_file(path: Path, algo: str, *, partial: int = 0) -> str:
    h = hashlib.new(algo)
    try:
        with path.open("rb") as fh:
            if partial:
                h.update(fh.read(partial))
            else:
                while True:
                    b = fh.read(_READ)
                    if not b:
                        break
                    h.update(b)
    except OSError:
        return ""
    return h.hexdigest()


def scan(paths, *, algo="sha256", recurse=True, follow_symlinks=False,
         exclude=(), min_size=1, full=False, baseline: set | None = None,
         progress=None) -> Result:
    _GID.clear()
    res = Result()
    by_size: dict[int, list[Path]] = {}
    for f in iter_files(paths, recurse=recurse,
                        follow_symlinks=follow_symlinks, exclude=exclude):
        try:
            sz = f.stat().st_size
        except OSError:
            continue
        if sz < min_size:
            continue
        res.scanned += 1
        by_size.setdefault(sz, []).append(f)

    for sz, group in by_size.items():
        need_hash = full or len(group) > 1 or baseline is not None
        for f in group:
            rec = FileRec(path=str(f), size=sz)
            if need_hash:
                rec.digest = hash_file(f, algo)
                res.hashed += 1
                if progress:
                    progress(res.hashed)
            res.files.append(rec)

    # group by digest
    for rec in res.files:
        if rec.digest:
            res.groups.setdefault(rec.digest, []).append(rec)

    for digest, recs in res.groups.items():
        recs.sort(key=lambda r: r.path)
        for i, r in enumerate(recs):
            r.group = _gid(digest)
            r.representative = (i == 0)
            if i:
                r.duplicate_of = recs[0].path
        if len(recs) > 1:
            res.reclaimable += recs[0].size * (len(recs) - 1)
        if baseline is not None:
            hit = digest in baseline
            for r in recs:
                r.status = "baseline-hit" if hit else "new"

    hashed_unique = len({r.digest for r in res.files if r.digest})
    unhashed = sum(1 for r in res.files if not r.digest)
    res.unique = hashed_unique + unhashed
    return res


_GID: dict[str, int] = {}


def _gid(digest: str) -> int:
    return _GID.setdefault(digest, len(_GID) + 1)


def load_hash_set(path: str) -> set[str]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    out: set[str] = set()
    if text.lstrip().startswith(("{", "[")):
        data = json.loads(text)
        entries = data.get("files", data) if isinstance(data, dict) else data
        if isinstance(entries, dict):
            entries = entries.values()
        for e in entries:
            if isinstance(e, dict):
                for k in ("sha256", "sha1", "md5", "digest", "hash"):
                    if e.get(k):
                        out.add(str(e[k]).lower())
    else:
        import csv
        rdr = csv.DictReader(text.splitlines())
        cols = {c.lower(): c for c in (rdr.fieldnames or [])}
        hcol = next((cols[c] for c in ("sha256", "sha1", "md5", "digest",
                                       "hash") if c in cols), None)
        if hcol:
            for row in rdr:
                if row.get(hcol):
                    out.add(row[hcol].strip().lower())
        else:
            for line in text.splitlines():
                tok = line.strip().split(",")[0].strip()
                if tok and all(c in "0123456789abcdefABCDEF" for c in tok):
                    out.add(tok.lower())
    return out
