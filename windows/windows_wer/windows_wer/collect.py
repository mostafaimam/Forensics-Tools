"""Discover .wer reports under a path and parse them."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from windows_wer import flags
from windows_wer.parse import parse_wer


@dataclass
class Result:
    rows: list = field(default_factory=list)
    reports: int = 0
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
                if f.is_file() and f.suffix.lower() == ".wer":
                    targets.append(f)

    for f in targets:
        try:
            raw = f.read_bytes()
        except OSError as e:
            res.errors.append(f"{f}: {e}")
            continue
        res.reports += 1
        res.sources.add(str(f))
        rep = parse_wer(raw, str(f))
        if rep.parse_error:
            res.errors.append(f"{f}: {rep.parse_error}")
        n, s = flags.classify(rep)
        rep.notable = n
        row = rep.row()
        row["severity"] = s
        res.rows.append(row)

    res.rows.sort(key=lambda r: (r.get("time") or "", r.get("app_name", "")))
    return res
