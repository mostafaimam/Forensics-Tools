"""Discover the thumbcache set under a path, parse and join with the index."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from windows_thumbcache import thumbcache as _tc

_WRITABLE = re.compile(r"[\\/](appdata|temp|programdata|public|downloads|"
                       r"\$recycle\.bin)[\\/]", re.I)
_REMOVABLE = re.compile(r"^[D-Zd-z]:\\|^\\\\")
_SENSITIVE_EXT = re.compile(r"\.(jpg|jpeg|png|gif|bmp|heic|cr2|nef|arw|"
                            r"tif|tiff|psd|mp4|mov|avi)$", re.I)


@dataclass
class Result:
    thumbnails: list = field(default_factory=list)
    dbs: list = field(default_factory=list)
    versions: set = field(default_factory=set)
    index_entries: int = 0
    errors: list = field(default_factory=list)


def _discover(p: Path) -> tuple[list[Path], Path | None]:
    if p.is_file():
        return [p], None
    caches = sorted(p.rglob("thumbcache_*.db"))
    idx = next((c for c in caches if c.name.lower() == "thumbcache_idx.db"),
               None)
    caches = [c for c in caches if c.name.lower() != "thumbcache_idx.db"]
    return caches, idx


def _flag(t: _tc.Thumbnail) -> list[str]:
    out = []
    ident = t.identifier or ""
    if "\\" in ident or "/" in ident:
        if _WRITABLE.search(ident):
            out.append(f"identifier points at a user-writable path ({ident})")
        elif _REMOVABLE.match(ident) and not ident[:2].lower().startswith(
                ("c:",)):
            out.append(f"identifier points at a removable / network path "
                       f"({ident})")
    if t.data_size and not t.fmt:
        out.append("thumbnail data is not a recognised image format")
    if t.data_size > 4 * 1024 * 1024:
        out.append(f"unusually large thumbnail ({t.data_size // 1024} KiB)")
    return out


def analyze(paths) -> Result:
    res = Result()
    for path in paths:
        caches, idx = _discover(Path(path))
        index: dict = {}
        if idx is not None:
            try:
                index = _tc.parse_index(idx.read_bytes())
                res.index_entries += len(index)
            except OSError as e:
                res.errors.append(f"{idx}: {e}")

        for c in caches:
            try:
                cf = _tc.parse_cache(c.read_bytes(), c.name)
            except (_tc.ThumbError, OSError) as e:
                res.errors.append(f"{c}: {e}")
                continue
            res.dbs.append(str(c))
            res.versions.add(cf.version_name)
            for t in cf.entries:
                ie = index.get(t.cache_id)
                if ie:
                    t.last_modified = ie.last_modified
                    t.idx_flags = ie.flags
                t.notable = _flag(t)
                res.thumbnails.append(t)

    res.thumbnails.sort(key=lambda t: (t.last_modified or "", t.db_name))
    return res
