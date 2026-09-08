"""Filesystem side of the picture: partial-download files + Zone.Identifier."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from browser_downloads.model import Download

_PARTIAL_EXT = (".crdownload", ".part", ".download", ".opdownload", ".partial",
                ".crswap", ".!ut")
_ZONE_SUFFIXES = (":Zone.Identifier", "_Zone.Identifier", ".Zone.Identifier")

_ZONE_KV = re.compile(r"^\s*(ZoneId|ReferrerUrl|HostUrl|LastWriterPackageFamilyName)"
                      r"\s*=\s*(.*?)\s*$", re.I)


def _zone_dict(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = _ZONE_KV.match(line)
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out


def read_zone_for(path: Path) -> dict | None:
    """Try the live NTFS ADS, then sibling files named <name>:Zone.Identifier."""
    for suff in _ZONE_SUFFIXES:
        cand = path.with_name(path.name + suff)
        try:
            if cand.exists():
                return _zone_dict(cand.read_text(encoding="utf-8",
                                                 errors="replace"))
        except OSError:
            pass
    if os.name == "nt":
        try:
            with open(f"{path}:Zone.Identifier", "r",
                      encoding="utf-8", errors="replace") as fh:
                return _zone_dict(fh.read())
        except OSError:
            pass
    return None


def _sha256(path: Path, cap: int = 512 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            read = 0
            while chunk := fh.read(1 << 20):
                h.update(chunk)
                read += len(chunk)
                if read > cap:
                    return ""
        return h.hexdigest()
    except OSError:
        return ""


def scan_tree(root: str, *, do_hash: bool = False) -> list[Download]:
    """Return Download rows for partial files and Zone.Identifier'd files
    found anywhere under *root*."""
    out: list[Download] = []
    base = Path(root)
    if base.is_file():
        files = [base]
        walk_dirs = []
    else:
        files = []
        walk_dirs = [base]
    for d in walk_dirs:
        for dirpath, _dn, filenames in os.walk(d):
            for fn in filenames:
                files.append(Path(dirpath) / fn)

    seen_zone: set = set()
    for f in files:
        name = f.name
        low = name.lower()

        if low.endswith(_PARTIAL_EXT):
            try:
                sz = f.stat().st_size
                mt = f.stat().st_mtime
            except OSError:
                sz = mt = 0
            real = str(f)
            for pe in _PARTIAL_EXT:
                if low.endswith(pe):
                    real = str(f)[: -len(pe)]
                    break
            from browser_downloads import timeconv as _t
            out.append(Download(
                source="partial-file", target_path=real,
                state="in-progress / interrupted",
                received_bytes=sz,
                end_time=_t.unix_s(mt) if mt else "",
                on_disk="partial", disk_size=sz,
                notable=[f"partial-download file left on disk ({f.name})"]))
            continue

        if any(low.endswith(s.lower()) for s in _ZONE_SUFFIXES):
            for s in _ZONE_SUFFIXES:
                if low.endswith(s.lower()):
                    real = f.with_name(name[: -len(s)])
                    break
            if str(real) in seen_zone:
                continue
            seen_zone.add(str(real))
            try:
                z = _zone_dict(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            present = real.exists()
            out.append(Download(
                source="zone.identifier", target_path=str(real),
                url=z.get("hosturl", ""), referrer=z.get("referrerurl", ""),
                zone_id=z.get("zoneid", ""), zone_host=z.get("hosturl", ""),
                zone_referrer=z.get("referrerurl", ""),
                on_disk="present" if present else "missing",
                disk_size=real.stat().st_size if present else 0,
                sha256=_sha256(real) if present and do_hash else "",
                notable=(["file marked internet-zone (MOTW)"]
                         if z.get("zoneid") in ("3", "4") else [])))

    return out


def correlate(downloads: list[Download], *, do_hash: bool = False) -> None:
    """Fill on_disk / disk_size / sha256 / zone_* for history downloads whose
    target file can be found."""
    for d in downloads:
        if d.source != "history-db" or not d.target_path:
            continue
        p = Path(d.target_path)
        try:
            exists = p.exists()
        except OSError:
            exists = False
        if exists:
            d.on_disk = "present"
            try:
                d.disk_size = p.stat().st_size
            except OSError:
                pass
            if do_hash:
                d.sha256 = _sha256(p)
            z = read_zone_for(p)
            if z:
                d.zone_id = z.get("zoneid", "") or d.zone_id
                d.zone_host = z.get("hosturl", "") or d.zone_host
                d.zone_referrer = z.get("referrerurl", "") or d.zone_referrer
        else:
            # a matching partial file?
            part = None
            for ext in _PARTIAL_EXT:
                cand = p.with_name(p.name + ext)
                if cand.exists():
                    part = cand
                    break
            d.on_disk = "partial" if part else "missing"
