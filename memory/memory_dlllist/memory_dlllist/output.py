"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["pid", "process", "base", "size", "name", "path", "protection",
           "notable", "confidence", "pool_tag", "phys_offset"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(m) -> dict:
    return {
        "pid": m.pid or "",
        "process": m.process,
        "base": f"{m.base:#x}",
        "size": m.size,
        "name": m.name,
        "path": m.path,
        "protection": m.protection,
        "notable": ";".join(m.notable),
        "confidence": m.confidence,
        "pool_tag": m.pool_tag,
        "phys_offset": f"{m.phys_offset:#x}",
    }


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows: list[dict], path: Path) -> None:
    Path(path).write_text(json.dumps(rows, indent=2), encoding="utf-8")


def render(mods) -> str:
    out = io.StringIO()
    last_pid = None
    for m in mods:
        if m.pid != last_pid:
            out.write(f"\n{m.process or '?'}  (pid {m.pid or '?'})\n")
            last_pid = m.pid
        flag = f"  [{','.join(m.notable)}]" if m.notable else ""
        out.write(f"  {m.base:#014x}  {m.size // 1024:>6} KiB  "
                  f"{(m.name or '<unbacked>'):<24} {m.path}{flag}\n")
    return out.getvalue()
