"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from browser_history import flags as _flags

COLUMNS = ["time", "browser", "profile", "kind", "url", "title", "from_url",
           "transition", "typed", "visit_count", "detail", "notable",
           "severity", "source_db"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(entry) -> dict:
    r = entry.row()
    r["severity"] = _flags.severity(entry.notable)
    return {k: r.get(k, "") for k in COLUMNS}


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows: list[dict], path: Path) -> None:
    Path(path).write_text(json.dumps(rows, indent=2), encoding="utf-8")


def render(rows: list[dict]) -> str:
    out = io.StringIO()
    for r in rows:
        mark = f"  [{r['severity']}]" if r.get("severity") not in ("none", "") \
            else ""
        t = (r["time"] or "----------------------")[:19]
        typ = {"visit": " ", "download": "↓", "search": "?"}.get(
            r["kind"], " ")
        line = f"{t}  {r['browser'][:7]:<7} {typ} {r['url'][:100]}{mark}"
        out.write(line + "\n")
        if r["kind"] == "download" and r["detail"]:
            out.write(f"{'':21}   -> {r['detail']}\n")
        elif r["kind"] == "search":
            out.write(f"{'':21}   {r['detail']}\n")
        if r["notable"]:
            out.write(f"{'':21}   ! {r['notable']}\n")
    return out.getvalue()
