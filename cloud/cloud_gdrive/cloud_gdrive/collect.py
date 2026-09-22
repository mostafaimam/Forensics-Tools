"""Tie discovery and generic DB dumping together."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_gdrive.discover import find_db_files
from cloud_gdrive.genericdb import dump_all_tables, is_sqlite, shape_rows

COLUMNS = ["source", "table", "path_hint", "time_hint", "size_hint",
          "row_json"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(targets: list[str]) -> Result:
    res = Result()
    files = []
    for t in targets:
        files.extend(find_db_files(t))
    if not files:
        res.warnings.append("no metadata_sqlite_db / snapshot.db / "
                            "sync_config.db file found")
        return res

    for f in files:
        if not is_sqlite(f):
            res.warnings.append(f"{f}: not a SQLite file - skipped")
            continue
        try:
            tables = dump_all_tables(str(f))
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"{f}: {e}")
            continue
        for table, (cols, rows) in tables.items():
            for r in shape_rows(str(f), table, cols, rows):
                res.rows.append(r)

    if not res.rows:
        res.warnings.append("no readable database rows found")
    return res
