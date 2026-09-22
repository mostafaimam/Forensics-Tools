"""Tie discovery and generic DB dumping together."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_box.discover import find_candidates
from cloud_box.genericdb import dump_all_tables, is_sqlite, shape_rows

COLUMNS = ["source", "table", "path_hint", "time_hint", "size_hint",
          "row_json"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(targets: list[str]) -> Result:
    res = Result()
    candidates = []
    for t in targets:
        candidates.extend(find_candidates(t))
    if not candidates:
        res.warnings.append("no database-shaped file found under a "
                            "Box-named path")
        return res

    found_sqlite = False
    for f in candidates:
        if not is_sqlite(f):
            continue
        found_sqlite = True
        try:
            tables = dump_all_tables(str(f))
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"{f}: {e}")
            continue
        for table, (cols, rows) in tables.items():
            for r in shape_rows(str(f), table, cols, rows):
                res.rows.append(r)

    if not found_sqlite:
        res.warnings.append(
            f"found {len(candidates)} candidate file(s) under a "
            f"Box-named path but none were plain SQLite")
    if not res.rows:
        res.warnings.append("no readable database rows found")
    return res
