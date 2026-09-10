"""Streaming multi-digest hashing and tree walking."""

from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ALGOS = ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")
_CHUNK = 1 << 20


@dataclass
class FileHash:
    path: str
    rel: str
    size: int
    mtime: str
    digests: dict = field(default_factory=dict)
    error: str = ""

    def row(self, algos) -> dict:
        d = {"path": self.rel or self.path, "size": self.size,
             "mtime": self.mtime}
        for a in algos:
            d[a] = self.digests.get(a, "")
        if self.error:
            d["error"] = self.error
        return d


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return ""


def hash_file(path: Path, algos, *, rel: str = "") -> FileHash:
    fh = FileHash(path=str(path), rel=rel, size=0, mtime="")
    try:
        st = path.stat()
        fh.size = st.st_size
        fh.mtime = _iso(st.st_mtime)
    except OSError as e:
        fh.error = str(e)
        return fh
    hs = {a: hashlib.new(a) if a not in ("sha3_256", "blake2b")
          else (hashlib.sha3_256() if a == "sha3_256" else hashlib.blake2b())
          for a in algos}
    try:
        with path.open("rb") as f:
            while True:
                b = f.read(_CHUNK)
                if not b:
                    break
                for h in hs.values():
                    h.update(b)
    except OSError as e:
        fh.error = str(e)
        return fh
    fh.digests = {a: h.hexdigest() for a, h in hs.items()}
    return fh


def _excluded(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(Path(rel).name, p)
              for p in patterns)


def walk_targets(paths, *, recurse=True, follow_symlinks=False,
                 exclude=(), file_list=None):
    """Yield (abs_path, rel_path) for every file to hash."""
    if file_list:
        for line in Path(file_list).read_text(
                encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                p = Path(line)
                if p.is_file():
                    yield p, line
        return
    for base in paths:
        b = Path(base)
        if b.is_file():
            yield b, b.name
            continue
        if not b.is_dir():
            continue
        for root, dirs, files in os.walk(b, followlinks=follow_symlinks):
            if not recurse:
                dirs[:] = []
            rootp = Path(root)
            for name in sorted(files):
                p = rootp / name
                rel = str(p.relative_to(b)).replace(os.sep, "/")
                if exclude and _excluded(rel, exclude):
                    continue
                if not follow_symlinks and p.is_symlink():
                    continue
                yield p, rel
            dirs.sort()


@dataclass
class HashResult:
    files: list = field(default_factory=list)
    algos: tuple = ()
    errors: int = 0


def hash_all(paths, algos, *, recurse=True, follow_symlinks=False,
             exclude=(), file_list=None, progress=None) -> HashResult:
    res = HashResult(algos=tuple(algos))
    n = 0
    for p, rel in walk_targets(paths, recurse=recurse,
                               follow_symlinks=follow_symlinks,
                               exclude=exclude, file_list=file_list):
        fh = hash_file(p, algos, rel=rel)
        res.files.append(fh)
        if fh.error:
            res.errors += 1
        n += 1
        if progress:
            progress(n)
    res.files.sort(key=lambda f: f.rel or f.path)
    return res
