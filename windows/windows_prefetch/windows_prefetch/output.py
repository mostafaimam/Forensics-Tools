"""CSV / JSON / JSONL / console writers.

CSV is UTF-8 with a BOM, RFC-4180 quoted, and formula-injection safe (a cell
starting with ``= + - @`` or a control char is apostrophe-prefixed).
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from windows_prefetch.models import SUMMARY_COLUMNS, PrefetchFile

_FILES_COLUMNS = ["executable", "source", "referenced_file"]


def _sanitise(value) -> str:
    s = "" if value is None else str(value)
    if s[:1] in ("=", "+", "-", "@") or s[:1] in ("\t", "\r", "\n"):
        return "'" + s
    return s


def write_summary_csv(items: list[PrefetchFile], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=SUMMARY_COLUMNS, dialect="excel")
        w.writeheader()
        for pf in items:
            w.writerow({k: _sanitise(v) for k, v in pf.summary_row().items()})


def write_files_csv(items: list[PrefetchFile], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_FILES_COLUMNS, dialect="excel")
        w.writeheader()
        for pf in items:
            for ref in pf.referenced_files:
                w.writerow({
                    "executable": _sanitise(pf.executable),
                    "source": _sanitise(pf.source),
                    "referenced_file": _sanitise(ref),
                })


def write_json(items: list[PrefetchFile], path: Path) -> None:
    path.write_text(
        json.dumps([pf.to_json() for pf in items], indent=2), encoding="utf-8"
    )


def write_jsonl(items: list[PrefetchFile], path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for pf in items:
            fh.write(json.dumps(pf.to_json(), separators=(",", ":")) + "\n")


def render_table(items: list[PrefetchFile]) -> str:
    out = io.StringIO()
    cols = [("executable", 40), ("run_count", 9), ("last_run_utc", 27),
            ("files", 6), ("ver", 4)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 92 + "\n")
    for pf in items:
        if pf.parse_error:
            out.write(f"[ERROR] {pf.source}: {pf.parse_error}\n")
            continue
        row = {
            "executable": pf.executable,
            "run_count": pf.run_count,
            "last_run_utc": pf.summary_row()["last_run_utc"],
            "files": pf.referenced_file_count,
            "ver": pf.format_version,
        }
        cells = []
        for h, w in cols:
            v = str(row[h])
            cells.append((v[: w - 1] + "…") if len(v) > w else v.ljust(w))
        out.write("  ".join(cells).rstrip() + "\n")
    return out.getvalue()
