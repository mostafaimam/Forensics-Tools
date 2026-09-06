from __future__ import annotations

import csv
import io
import json
from pathlib import Path

RECORD_COLUMNS = ["timestamp_utc", "host", "facility", "severity", "tag", "pid",
                  "message", "format", "source_file", "line"]
EVENT_COLUMNS = ["timestamp_utc", "category", "action", "result", "user",
                 "target_user", "source_ip", "source_port", "tty", "command",
                 "detail", "host", "tag", "source_file", "line"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else ""


def record_row(r) -> dict:
    return {
        "timestamp_utc": _iso(r.timestamp), "host": r.host,
        "facility": r.facility, "severity": r.severity, "tag": r.tag,
        "pid": r.pid, "message": r.message.replace("\n", "\\n"),
        "format": r.format, "source_file": r.source_file, "line": r.line_no,
    }


def event_row(e) -> dict:
    return {
        "timestamp_utc": _iso(e.timestamp), "category": e.category,
        "action": e.action, "result": e.result, "user": e.user,
        "target_user": e.target_user, "source_ip": e.source_ip,
        "source_port": e.source_port, "tty": e.tty,
        "command": e.command.replace("\n", "\\n"), "detail": e.detail,
        "host": e.host, "tag": e.tag, "source_file": e.source_file,
        "line": e.line_no,
    }


def write_csv(rows, columns, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in columns})


def write_json(rows, path: Path) -> None:
    path.write_text(json.dumps(list(rows), indent=2, default=str),
                    encoding="utf-8")


def render_table(rows, columns, limit: int = 200) -> str:
    rows = list(rows)
    widths = {c: min(max(len(c), *(len(str(r.get(c, ""))) for r in rows[:limit]))
                     if rows else len(c), 60) for c in columns}
    out = io.StringIO()
    out.write("  ".join(c.upper().ljust(widths[c]) for c in columns).rstrip()
              + "\n")
    out.write("-" * min(sum(widths.values()) + 2 * len(columns), 200) + "\n")
    for r in rows[:limit]:
        out.write("  ".join(
            (str(r.get(c, ""))[: widths[c] - 1] + "…")
            if len(str(r.get(c, ""))) > widths[c]
            else str(r.get(c, "")).ljust(widths[c]) for c in columns
        ).rstrip() + "\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more (use --csv)\n")
    return out.getvalue()
