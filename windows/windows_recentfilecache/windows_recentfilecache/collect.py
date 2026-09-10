"""Find RecentFileCache.bcf files and parse them."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from windows_recentfilecache import flags
from windows_recentfilecache.parse import parse

_NAME = re.compile(r"RecentFileCache\.bcf$", re.I)


@dataclass
class Result:
    rows: list = field(default_factory=list)
    files: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def collect(paths) -> Result:
    res = Result()
    targets: list[Path] = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            targets.append(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and _NAME.search(f.name):
                    targets.append(f)

    for f in targets:
        try:
            data = f.read_bytes()
            stat = f.stat()
        except OSError as e:
            res.errors.append(f"{f}: {e}")
            continue
        res.files += 1
        res.sources.add(str(f))
        parsed = parse(data)
        if parsed.parse_error:
            res.errors.append(f"{f}: {parsed.parse_error}")
        if not parsed.header_ok:
            res.errors.append(f"{f}: unexpected signature {parsed.signature}")
        mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc)\
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        for e in parsed.entries:
            n, s = flags.classify(e.path)
            row = e.row()
            row["file_mtime"] = mtime
            row["source"] = str(f)
            row["notable"] = ";".join(n)
            row["severity"] = s
            res.rows.append(row)
        if parsed.trailing_bytes > 8:
            res.errors.append(
                f"{f}: {parsed.trailing_bytes} trailing bytes after the "
                f"last entry")

    res.rows.sort(key=lambda r: (r.get("source", ""), r.get("index", 0)))
    return res
