from __future__ import annotations

import csv
import io
import json
from pathlib import Path

RECORD_COLUMNS = ["index", "timestamp_utc", "type", "user", "line", "host",
                  "address", "pid", "session", "exit_termination", "exit_code",
                  "source_file"]
SESSION_COLUMNS = ["user", "line", "host", "address", "pid", "login_utc",
                   "logout_utc", "duration_seconds", "still_open", "source_file"]
LASTLOG_COLUMNS = ["uid", "last_login_utc", "line", "host", "source_file"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else ""


def record_row(r, source: str) -> dict:
    return {
        "index": r.index, "timestamp_utc": _iso(r.timestamp),
        "type": r.type_name, "user": r.user, "line": r.line, "host": r.host,
        "address": r.address, "pid": r.pid, "session": r.session,
        "exit_termination": r.exit_termination, "exit_code": r.exit_code,
        "source_file": source,
    }


def session_row(s, source: str) -> dict:
    return {
        "user": s.user, "line": s.line, "host": s.host, "address": s.address,
        "pid": s.pid, "login_utc": _iso(s.login), "logout_utc": _iso(s.logout),
        "duration_seconds": "" if s.duration_seconds is None
        else round(s.duration_seconds, 3),
        "still_open": "yes" if s.still_open else "no", "source_file": source,
    }


def lastlog_row(e, source: str) -> dict:
    return {"uid": e.uid, "last_login_utc": _iso(e.timestamp),
            "line": e.line, "host": e.host, "source_file": source}


def write_csv(rows, columns, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(v) for k, v in r.items()})


def write_json(rows, path: Path) -> None:
    path.write_text(json.dumps(list(rows), indent=2, default=str),
                    encoding="utf-8")


def render_table(rows, columns, limit: int = 200) -> str:
    rows = list(rows)
    widths = {c: min(max(len(c), *(len(str(r.get(c, ""))) for r in rows[:limit]))
                     if rows else len(c), 40) for c in columns}
    out = io.StringIO()
    out.write("  ".join(c.upper().ljust(widths[c]) for c in columns).rstrip() + "\n")
    out.write("-" * min(sum(widths.values()) + 2 * len(columns), 160) + "\n")
    for r in rows[:limit]:
        out.write("  ".join(
            (str(r.get(c, ""))[: widths[c] - 1] + "…")
            if len(str(r.get(c, ""))) > widths[c]
            else str(r.get(c, "")).ljust(widths[c]) for c in columns
        ).rstrip() + "\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more (use --csv)\n")
    return out.getvalue()
