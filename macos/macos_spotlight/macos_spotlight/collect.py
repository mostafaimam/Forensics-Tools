"""Resolve targets to store files and carve classified strings from each."""

from __future__ import annotations

from dataclasses import dataclass, field

from macos_spotlight.carve import find_stores, scan_file

COLUMNS = ["source", "offset", "encoding", "category", "text"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(targets: list[str], *, min_len=6, encodings=("ascii", "utf-16le"),
           categories=None, hex_offset=False) -> Result:
    res = Result()
    for target in targets:
        stores = find_stores(target)
        if not stores:
            res.warnings.append(f"no store file found under {target}")
            continue
        for store in stores:
            res.sources.append(str(store))
            for hit in scan_file(str(store), str(store), min_len=min_len,
                                 encodings=encodings, categories=categories):
                res.rows.append(hit.row(hex_offset))
    return res
