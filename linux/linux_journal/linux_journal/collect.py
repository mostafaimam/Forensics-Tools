"""Discover journal files under a root and merge them into one timeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from linux_journal import flags as _flags
from linux_journal import journalfile as _jf

_GLOBS = [
    "var/log/journal/*/*.journal",
    "var/log/journal/*/*.journal~",
    "run/log/journal/*/*.journal",
]


@dataclass
class Result:
    entries: list = field(default_factory=list)
    files: list = field(default_factory=list)
    boots: dict = field(default_factory=dict)   # boot_id -> (first, last) iso
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    lz4_skipped: int = 0
    zstd_skipped: int = 0


def discover(path: str) -> list[str]:
    p = Path(path)
    if p.is_file():
        return [str(p)]
    out: list[str] = []
    for g in _GLOBS:
        out += [str(m) for m in p.glob(g) if m.is_file()]
    return sorted(set(out))


def collect(paths, *, progress=None) -> Result:
    res = Result()
    for path in paths:
        for f in discover(str(path)):
            res.files.append(f)
            pr = _jf.ParseResult()
            try:
                _jf.read(f, pr)
            except (_jf.JournalError, OSError, ValueError) as e:
                res.errors.append(f"{f}: {e}")
                continue
            res.lz4_skipped += pr.lz4_skipped
            res.zstd_skipped += pr.zstd_skipped
            if pr.bad_objects:
                res.warnings.append(f"{Path(f).name}: stopped early after "
                                    f"{pr.bad_objects} unreadable object(s)")
            for e in pr.entries:
                e.notable = _flags.flag(e)
                res.entries.append(e)
                if progress and len(res.entries) % 20000 == 0:
                    progress(len(res.entries))

    if res.lz4_skipped:
        res.warnings.append(f"{res.lz4_skipped} LZ4-compressed field(s) not "
                            f"inflated (needs a non-stdlib codec)")
    if res.zstd_skipped:
        res.warnings.append(f"{res.zstd_skipped} ZSTD-compressed field(s) not "
                            f"inflated (needs a non-stdlib codec)")

    res.entries.sort(key=lambda e: (e.realtime_us or 0, e.seqnum))
    for e in res.entries:
        bid = e.boot_id or "?"
        lo, hi = res.boots.get(bid, ("", ""))
        iso = e.iso
        if iso:
            res.boots[bid] = (lo or iso, iso)
    return res
