from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["timestamp_utc", "user", "shell", "command", "notable", "note",
           "source_file", "line"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else ""


def entry_row(e) -> dict:
    return {
        "timestamp_utc": _iso(e.timestamp),
        "user": e.user,
        "shell": e.shell,
        "command": e.command.replace("\n", "\\n"),
        "notable": " ; ".join(e.notable),
        "note": e.note,
        "source_file": e.source_file,
        "line": e.line_no or "",
    }


def write_csv(rows, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path: Path) -> None:
    path.write_text(json.dumps(list(rows), indent=2, default=str),
                    encoding="utf-8")


def render_table(rows, limit: int = 200) -> str:
    rows = list(rows)
    cols = ["timestamp_utc", "user", "shell", "command", "notable"]
    widths = {c: min(max(len(c), *(len(str(r.get(c, ""))) for r in rows[:limit]))
                     if rows else len(c), 70) for c in cols}
    out = io.StringIO()
    out.write("  ".join(c.upper().ljust(widths[c]) for c in cols).rstrip() + "\n")
    out.write("-" * min(sum(widths.values()) + 2 * len(cols), 200) + "\n")
    for r in rows[:limit]:
        out.write("  ".join(
            (str(r.get(c, ""))[: widths[c] - 1] + "…")
            if len(str(r.get(c, ""))) > widths[c]
            else str(r.get(c, "")).ljust(widths[c]) for c in cols
        ).rstrip() + "\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more (use --csv)\n")
    return out.getvalue()
