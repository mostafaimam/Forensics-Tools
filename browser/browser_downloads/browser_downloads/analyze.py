"""Collect downloads from history stores + the filesystem, then flag."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from browser_downloads import chromium as _chromium
from browser_downloads import discover as _discover
from browser_downloads import firefox as _firefox
from browser_downloads import flags as _flags
from browser_downloads import fsscan as _fsscan


@dataclass
class Result:
    downloads: list = field(default_factory=list)
    stores: int = 0
    from_disk: int = 0
    errors: list = field(default_factory=list)


def _key(d) -> tuple:
    tp = (d.target_path or "").replace("\\", "/").rstrip("/").lower()
    if tp:
        return ("t", tp)
    return ("u", d.url or d.zone_host, d.filename)


def analyze(paths, *, scan_fs: bool = True, do_hash: bool = False,
            progress=None) -> Result:
    res = Result()
    downloads: list = []
    fs_roots: list[str] = []

    for path in paths:
        p = Path(path)
        try:
            stores = _discover.find(str(p))
        except OSError as e:
            res.errors.append(f"{path}: {e}")
            continue
        if stores:
            for st in stores:
                res.stores += 1
                try:
                    if st.family == "chromium":
                        downloads += _chromium.parse(st.path)
                    elif st.family == "firefox-places":
                        downloads += _firefox.parse(st.path)
                    elif st.family == "firefox-legacy":
                        downloads += _firefox.parse_legacy(st.path)
                except Exception as e:  # noqa: BLE001
                    res.errors.append(f"{st.path}: {e}")
            if p.is_dir():
                fs_roots.append(str(p))
        elif p.is_dir():
            fs_roots.append(str(p))
        elif p.is_file():
            res.errors.append(f"{path}: not a recognised download-history "
                              f"store")

    # filesystem side
    if scan_fs:
        for root in fs_roots:
            try:
                found = _fsscan.scan_tree(root, do_hash=do_hash)
                res.from_disk += len(found)
                downloads += found
            except OSError as e:
                res.errors.append(f"{root}: {e}")
        _fsscan.correlate(downloads, do_hash=do_hash)

    # merge: prefer a history row, absorb disk-only info into it
    merged: dict = {}
    for d in downloads:
        k = _key(d)
        if k in merged:
            cur = merged[k]
            if cur.source == "history-db":
                _absorb(cur, d)
            elif d.source == "history-db":
                _absorb(d, cur)
                merged[k] = d
            else:
                _absorb(cur, d)
        else:
            merged[k] = d

    out = list(merged.values())
    for d in out:
        d.notable = _flags.flag(d)
    res.downloads = sorted(
        out, key=lambda d: (not d.start_time, d.start_time or d.end_time or ""))
    return res


def _absorb(keep, other) -> None:
    for attr in ("url", "referrer", "zone_id", "zone_host", "zone_referrer",
                 "sha256", "mime", "end_time"):
        if not getattr(keep, attr) and getattr(other, attr):
            setattr(keep, attr, getattr(other, attr))
    if other.on_disk and (not keep.on_disk or keep.on_disk == "missing"):
        keep.on_disk = other.on_disk
        keep.disk_size = other.disk_size or keep.disk_size
    for n in other.notable:
        if n not in keep.notable:
            keep.notable.append(n)
