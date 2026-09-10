"""Walk a file set, compute the digests, cluster by similarity."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from analysis_fuzzyhash import ctph, locality, pehash

_MAX_FILE = 64 << 20


@dataclass
class Item:
    path: str
    size: int
    sha256: str = ""
    ctph: str = ""
    locality: str = ""
    imphash: str = ""
    rich_hash: str = ""
    is_pe: bool = False
    cluster: int = 0
    representative: bool = False
    best_match: str = ""
    best_score: int = 0
    error: str = ""

    def row(self) -> dict:
        return {
            "path": self.path, "size": self.size, "sha256": self.sha256,
            "ctph": self.ctph, "locality": self.locality,
            "imphash": self.imphash, "rich_hash": self.rich_hash,
            "is_pe": self.is_pe, "cluster": self.cluster or "",
            "representative": "yes" if self.representative else "",
            "best_match": self.best_match, "best_score": self.best_score,
            "error": self.error,
        }


@dataclass
class Result:
    items: list = field(default_factory=list)
    clusters: dict = field(default_factory=dict)     # id -> [paths]
    errors: int = 0


def _walk(paths, recurse, exclude):
    import fnmatch
    for base in paths:
        b = Path(base)
        if b.is_file():
            yield b
            continue
        if not b.is_dir():
            continue
        for root, dirs, files in os.walk(b):
            if not recurse:
                dirs[:] = []
            for name in sorted(files):
                p = Path(root) / name
                if exclude and any(fnmatch.fnmatch(name, g) for g in exclude):
                    continue
                yield p


def _digest_file(p: Path) -> Item:
    try:
        st = p.stat()
    except OSError as e:
        return Item(path=str(p), size=0, error=str(e))
    it = Item(path=str(p), size=st.st_size)
    if st.st_size > _MAX_FILE:
        it.error = "file too large"
        return it
    try:
        data = p.read_bytes()
    except OSError as e:
        it.error = str(e)
        return it
    it.sha256 = hashlib.sha256(data).hexdigest()
    it.ctph = ctph.hash_bytes(data)
    it.locality = locality.digest(data)
    pe = pehash.parse_pe(data)
    it.is_pe = pe["is_pe"]
    it.imphash = pe["imphash"]
    it.rich_hash = pe["rich_hash"]
    return it


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def scan(paths, *, recurse=True, exclude=(), threshold=70, progress=None,
         baseline=None) -> Result:
    res = Result()
    files = list(_walk(paths, recurse, exclude))
    for i, p in enumerate(files):
        it = _digest_file(p)
        if it.error:
            res.errors += 1
        res.items.append(it)
        if progress:
            progress(i + 1, len(files))

    valid = [it for it in res.items if it.ctph and not it.error]
    uf = _UF(len(valid))
    for i in range(len(valid)):
        for j in range(i + 1, len(valid)):
            a, b = valid[i], valid[j]
            score = ctph.compare(a.ctph, b.ctph)
            if score < threshold and a.locality and b.locality:
                loc = locality.similarity(a.locality, b.locality)
                # locality is noisy for text-like data; only let a *strong*
                # locality match rescue a pair CTPH could not relate
                if loc >= 80:
                    score = max(score, loc)
            if a.is_pe and b.is_pe and a.imphash and a.imphash == b.imphash:
                score = max(score, max(threshold, 60))
            if score > a.best_score:
                a.best_score, a.best_match = score, b.path
            if score > b.best_score:
                b.best_score, b.best_match = score, a.path
            if score >= threshold:
                uf.union(i, j)

    groups: dict[int, list[int]] = {}
    for idx in range(len(valid)):
        groups.setdefault(uf.find(idx), []).append(idx)
    cid = 0
    for root, members in groups.items():
        if len(members) < 2:
            continue
        cid += 1
        members.sort(key=lambda m: (-valid[m].size, valid[m].path))
        for k, m in enumerate(members):
            valid[m].cluster = cid
            valid[m].representative = (k == 0)
        res.clusters[cid] = [valid[m].path for m in members]

    if baseline:
        for it in valid:
            for bh in baseline:
                s = ctph.compare(it.ctph, bh)
                if s > it.best_score:
                    it.best_score, it.best_match = s, "(baseline)"

    res.items.sort(key=lambda it: (it.cluster or 1 << 30, it.path))
    return res
