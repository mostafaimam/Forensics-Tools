"""Tie discovery, settings parsing, and generic DB dumping together."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_onedrive.discover import find_db_files, find_settings_files
from cloud_onedrive.genericdb import dump_all_tables, is_sqlite, shape_rows
from cloud_onedrive.settings import parse_settings_file

COLUMNS = ["kind", "source", "table_or_key", "path_hint", "time_hint",
          "size_hint", "value_or_row_json"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(targets: list[str]) -> Result:
    res = Result()
    db_files: list = []
    settings_files: list = []
    for t in targets:
        db_files.extend(find_db_files(t))
        settings_files.extend(find_settings_files(t))

    if not db_files and not settings_files:
        res.warnings.append("no OneDrive settings/*.ini or "
                            "SyncEngineDatabase file found")
        return res

    for f in settings_files:
        kv = parse_settings_file(f)
        for k, v in kv.items():
            res.rows.append({
                "kind": "setting", "source": str(f), "table_or_key": k,
                "path_hint": "", "time_hint": "", "size_hint": "",
                "value_or_row_json": v,
            })

    for f in db_files:
        if not is_sqlite(f):
            res.warnings.append(
                f"{f}: not a SQLite file (an older OneDrive client uses "
                f"an ESE/JET-format database - open it directly with "
                f"windows_esedb instead)")
            continue
        try:
            tables = dump_all_tables(str(f))
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"{f}: {e}")
            continue
        for table, (cols, rows) in tables.items():
            for r in shape_rows(str(f), table, cols, rows):
                res.rows.append({
                    "kind": "db_row", "source": r["source"],
                    "table_or_key": r["table"],
                    "path_hint": r["path_hint"], "time_hint": r["time_hint"],
                    "size_hint": r["size_hint"],
                    "value_or_row_json": r["row_json"],
                })

    if not res.rows:
        res.warnings.append("no readable settings or database rows found")
    return res
