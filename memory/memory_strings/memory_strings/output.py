from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["phys", "encoding", "length", "category", "match", "text"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(h) -> dict:
    return {"phys": f"{h.phys:#x}", "encoding": h.encoding, "length": h.length,
            "category": h.category, "match": h.match,
            "text": h.text.replace("\n", "\\n").replace("\r", "")}


def write_csv(rows, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path: Path) -> None:
    path.write_text(json.dumps(list(rows), indent=2, default=str),
                    encoding="utf-8")


def render(rows, limit=500) -> str:
    out = io.StringIO()
    rows = list(rows)
    for r in rows[:limit]:
        tag = f"[{r['category']}] " if r["category"] else ""
        out.write(f"{r['phys']:>14}  {r['encoding']:<9} {tag}{r['text']}\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more (use --csv)\n")
    return out.getvalue()
