"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["name", "display_name", "type", "state", "pid", "binary_path",
           "notable", "severity", "confidence", "phys_offset"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(r) -> dict:
    return {
        "name": r.name,
        "display_name": r.display_name,
        "type": r.type,
        "state": r.state,
        "pid": r.pid or "",
        "binary_path": r.binary_path,
        "notable": ";".join(r.notable),
        "severity": r.severity,
        "confidence": r.confidence,
        "phys_offset": f"{r.phys_offset:#x}",
    }


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows: list[dict], path: Path) -> None:
    Path(path).write_text(json.dumps(rows, indent=2), encoding="utf-8")


def render(rows) -> str:
    out = io.StringIO()
    out.write(f"{'STATE':<16} {'TYPE':<22} {'NAME':<28} BINARY\n")
    out.write("-" * 110 + "\n")
    for r in rows:
        mark = f"  [{r.severity}]" if r.severity != "none" else ""
        out.write(f"{r.state:<16} {r.type:<22} {r.name[:28]:<28} "
                  f"{r.binary_path}{mark}\n")
        if r.notable:
            out.write(f"{'':<16} {'':<22} {'':<28} ! {', '.join(r.notable)}\n")
    return out.getvalue()
