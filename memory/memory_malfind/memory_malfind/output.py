"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

COLUMNS = ["pid", "process", "start", "end", "size", "protection",
           "vad_type", "verdict", "confidence", "entropy", "detail",
           "pool_tag", "phys_offset"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(d) -> dict:
    return {
        "pid": d.pid or "",
        "process": d.process,
        "start": f"{d.start:#x}",
        "end": f"{d.end:#x}",
        "size": d.size,
        "protection": d.protection,
        "vad_type": d.vad_type,
        "verdict": d.verdict,
        "confidence": d.confidence,
        "entropy": d.entropy,
        "detail": d.detail,
        "pool_tag": d.pool_tag,
        "phys_offset": f"{d.phys_offset:#x}",
    }


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows: list[dict], path: Path) -> None:
    Path(path).write_text(json.dumps(rows, indent=2), encoding="utf-8")


def render(detections) -> str:
    if not detections:
        return "no injected / unbacked executable memory found\n"
    out = []
    for d in detections:
        who = f"{d.process or '?'} (pid {d.pid})" if d.pid else "unattributed"
        out.append(
            f"[{d.confidence.upper()}] {d.verdict}  -  {who}\n"
            f"    range      {d.start:#x} - {d.end:#x}  ({d.size // 1024} KiB)\n"
            f"    protection {d.protection}   vad {d.vad_type}   "
            f"tag {d.pool_tag}   entropy {d.entropy}\n"
            f"    {d.detail}\n"
            + "\n".join("    " + line for line in d.hexdump.splitlines())
            + "\n")
    return "\n".join(out)
