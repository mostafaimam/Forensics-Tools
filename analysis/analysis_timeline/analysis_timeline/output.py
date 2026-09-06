from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from analysis_timeline.model import COLUMNS, Event


def _sanitise(value) -> str:
    s = "" if value is None else str(value)
    if s[:1] in ("=", "+", "-", "@") or s[:1] in ("\t", "\r", "\n"):
        return "'" + s
    return s


def write_csv(events: list[Event], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, dialect="excel")
        w.writeheader()
        for e in events:
            w.writerow({k: _sanitise(v) for k, v in e.as_row().items()})


def write_jsonl(events: list[Event], path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e.as_json(), separators=(",", ":"), default=str) + "\n")


def write_bodyfile(events: list[Event], path: Path) -> None:
    """TSK 3.x bodyfile: pipe-delimited, epoch seconds; type in the name."""
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for e in events:
            epoch = int(e.timestamp.timestamp())
            name = f"{e.description} ({e.timestamp_type})".replace("|", "/")
            fh.write(f"0|{name}|0|0|0|0|0|{epoch}|{epoch}|{epoch}|{epoch}\n")


def render_table(events: list[Event], limit: int = 200) -> str:
    out = io.StringIO()
    cols = [("timestamp_utc", 24), ("timestamp_type", 14),
            ("tool", 15), ("description", 70)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 120 + "\n")
    for e in events[:limit]:
        row = e.as_row()
        cells = []
        for h, w in cols:
            v = str(row[h])
            cells.append((v[: w - 1] + "…") if len(v) > w else v.ljust(w))
        out.write("  ".join(cells).rstrip() + "\n")
    if len(events) > limit:
        out.write(f"... {len(events) - limit} more rows (see --csv / --jsonl)\n")
    return out.getvalue()
