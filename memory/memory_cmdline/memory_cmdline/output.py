"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["pid", "process", "image_path", "command_line", "current_dir",
           "window_title", "notable", "severity", "phys_offset"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(r) -> dict:
    return {
        "pid": r.pid or "",
        "process": r.process,
        "image_path": r.image_path,
        "command_line": r.command_line,
        "current_dir": r.current_dir,
        "window_title": r.window_title,
        "notable": ";".join(r.notable),
        "severity": r.severity,
        "phys_offset": f"{r.phys_offset:#x}",
    }


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path: Path, full=None) -> None:
    if full is not None:
        data = [{
            "pid": r.pid, "process": r.process, "image_path": r.image_path,
            "command_line": r.command_line, "current_dir": r.current_dir,
            "window_title": r.window_title, "dll_path": r.dll_path,
            "environment": r.environment, "notable": r.notable,
            "severity": r.severity, "resolved": r.resolved,
            "phys_offset": hex(r.phys_offset),
        } for r in full]
    else:
        data = rows
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        tag = f"  [{r.severity}]" if r.severity != "none" else ""
        out.write(f"pid {r.pid:<6} {r.process}{tag}\n")
        if r.command_line:
            out.write(f"    cmd   {r.command_line}\n")
        elif r.image_path:
            out.write(f"    img   {r.image_path}  (no command line recovered)\n")
        else:
            out.write("    (command line not recovered)\n")
        if r.current_dir:
            out.write(f"    cwd   {r.current_dir}\n")
        if r.notable:
            out.write(f"    !     {', '.join(r.notable)}\n")
        out.write("\n")
    return out.getvalue()
