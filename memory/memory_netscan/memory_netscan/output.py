"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["proto", "role", "state", "local_addr", "local_port",
           "remote_addr", "remote_port", "pid", "process", "create_time",
           "confidence", "pool_tag", "phys_offset"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(e) -> dict:
    return {
        "proto": e.proto,
        "role": e.role,
        "state": e.state,
        "local_addr": e.local_addr,
        "local_port": e.local_port or "",
        "remote_addr": e.remote_addr,
        "remote_port": e.remote_port or "",
        "pid": e.pid or "",
        "process": e.process,
        "create_time": e.create_time,
        "confidence": e.confidence,
        "pool_tag": e.pool_tag,
        "phys_offset": f"{e.phys_offset:#x}",
    }


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
    out.write(f"{'PROTO':<5} {'ROLE':<9} {'STATE':<12} "
              f"{'LOCAL':<24} {'REMOTE':<24} {'PID':>6}  {'PROCESS':<16} "
              f"{'CREATED (UTC)':<20} CONF\n")
    out.write("-" * 130 + "\n")
    for r in rows:
        loc = f"{r['local_addr']}:{r['local_port']}" if r['local_port'] \
            else r['local_addr']
        rem = f"{r['remote_addr']}:{r['remote_port']}" if r['remote_port'] \
            else (r['remote_addr'] or "*")
        out.write(f"{r['proto']:<5} {r['role']:<9} {r['state']:<12} "
                  f"{loc:<24} {rem:<24} {str(r['pid']):>6}  "
                  f"{r['process'][:16]:<16} {r['create_time']:<20} "
                  f"{r['confidence']}\n")
    return out.getvalue()
