"""Walk paths, analyse every image / video, optionally group by look-alike."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from analysis_gallery import phash
from analysis_gallery.media import MediaFile, analyze


@dataclass
class Result:
    files: list[MediaFile] = field(default_factory=list)
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    groups: int = 0

    @property
    def images(self) -> int:
        return sum(1 for f in self.files if f.category == "image")

    @property
    def videos(self) -> int:
        return sum(1 for f in self.files if f.category == "video")

    @property
    def with_gps(self) -> int:
        return sum(1 for f in self.files if f.has_gps)

    @property
    def with_exif(self) -> int:
        return sum(1 for f in self.files if f.has_exif)


def _iter_files(paths, follow_symlinks: bool):
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            for root, dirs, names in os.walk(p, followlinks=follow_symlinks):
                dirs.sort()
                for name in sorted(names):
                    yield Path(root) / name


def scan(paths, *, phash_on: bool = False, threshold: int = 10,
         want_thumbs: bool = False, hash_files: bool = True,
         include=None, exclude=None, min_size: int = 0,
         categories=None, follow_symlinks: bool = False,
         max_decode_mp: float | None = None, progress=None) -> Result:
    res = Result()
    inc = list(include or [])
    exc = list(exclude or [])
    cats = set(categories) if categories else None

    for fp in _iter_files(paths, follow_symlinks):
        name = fp.name
        if inc and not any(fnmatch.fnmatch(name, g) for g in inc):
            continue
        if exc and any(fnmatch.fnmatch(name, g) for g in exc):
            continue
        try:
            if fp.stat().st_size < max(1, min_size):
                continue
        except OSError:
            res.errors += 1
            continue
        try:
            mf = analyze(fp, want_pixels=phash_on, want_thumb=want_thumbs,
                         hash_files=hash_files, max_decode_mp=max_decode_mp)
        except Exception:  # noqa: BLE001
            res.errors += 1
            continue
        if mf is None:
            res.skipped += 1
            continue
        if cats and mf.category not in cats:
            continue
        res.files.append(mf)
        res.scanned += 1
        if progress and res.scanned % 25 == 0:
            progress(res.scanned)

    if phash_on:
        hashes = [int(f.phash, 16) if f.phash else None for f in res.files]
        gids = phash.group(hashes, threshold)
        for f, g in zip(res.files, gids):
            f.phash_group = g
        res.groups = max(gids) if gids else 0

    res.files.sort(key=lambda f: (f.phash_group == 0, f.phash_group,
                                  f.datetime_original or "~", f.path))
    return res
