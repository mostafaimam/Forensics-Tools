"""Result writers: CSV, JSON, JSONL, and a console table.

CSV is UTF-8 with a BOM (so spreadsheets read non-ASCII paths correctly),
RFC-4180 quoted, and formula-injection neutralised (cells starting with
``= + - @`` or a control character are prefixed with an apostrophe).
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from trace_recycle.models import ROW_COLUMNS, RecycleRecord


def _sanitise(value) -> str:
    s = "" if value is None else str(value)
    if s[:1] in ("=", "+", "-", "@") or s[:1] in ("\t", "\r", "\n"):
        return "'" + s
    return s


def write_csv(records: list[RecycleRecord], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=ROW_COLUMNS, dialect="excel")
        w.writeheader()
        for r in records:
            w.writerow({k: _sanitise(v) for k, v in r.as_row().items()})


def _json_obj(r: RecycleRecord) -> dict:
    row = r.as_row()
    row["original_size"] = r.original_size
    row["deleted_utc"] = r.deleted_utc_iso or None
    row["index"] = r.index
    row["content_present"] = r.content_present
    row["content_is_dir"] = r.content_is_dir
    row["active"] = r.active
    row["warnings"] = list(r.warnings)
    return row


def write_json(records: list[RecycleRecord], path: Path) -> None:
    path.write_text(
        json.dumps([_json_obj(r) for r in records], indent=2), encoding="utf-8"
    )


def write_jsonl(records: list[RecycleRecord], path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(_json_obj(r), separators=(",", ":")) + "\n")


_TABLE_COLS = [
    ("deleted_utc", 27),
    ("original_size", 12),
    ("drive", 5),
    ("content_present", 7),
    ("original_path", 60),
]


def render_table(records: list[RecycleRecord]) -> str:
    out = io.StringIO()
    header = "  ".join(name.upper().ljust(width) for name, width in _TABLE_COLS)
    out.write(header.rstrip() + "\n")
    out.write("-" * len(header) + "\n")
    for r in records:
        row = r.as_row()
        if r.parse_error:
            out.write(f"[ERROR] {r.source}: {r.parse_error}\n")
            continue
        cells = []
        for name, width in _TABLE_COLS:
            val = str(row.get(name, ""))
            if len(val) > width:
                val = val[: width - 1] + "…"
            cells.append(val.ljust(width))
        out.write("  ".join(cells).rstrip() + "\n")
    return out.getvalue()
