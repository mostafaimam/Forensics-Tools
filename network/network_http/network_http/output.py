"""Manifest CSV / JSON + text render."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from network_http import flags as _flags

COLUMNS = ["time", "direction", "client", "server", "server_port", "method",
           "url", "status", "content_type", "detected_type", "encoding",
           "filename", "size", "sha256", "md5", "truncated", "user_agent",
           "server_hdr", "notable", "severity"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(o) -> dict:
    r = o.row()
    r["severity"] = _flags.severity(o.notable)
    return r


def write_csv(rows, path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path: Path) -> None:
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        arrow = "<-" if r["direction"] == "download" else "->"
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        out.write(f"{r['time'][:19]:<21} {r['client']} {arrow} {r['server']}  "
                  f"{r['method']} {r['url']}{mark}\n")
        line = f"    {r['filename'] or '(unnamed)'}  {r['size']:,} B  "
        if r["content_type"]:
            line += f"{r['content_type']} "
        if r["detected_type"] and r["detected_type"] != r["content_type"]:
            line += f"(bytes: {r['detected_type']}) "
        if r["encoding"]:
            line += f"[{r['encoding']}] "
        out.write(line + "\n")
        out.write(f"    sha256 {r['sha256']}\n")
        if r["notable"]:
            out.write(f"    !      {', '.join(r['notable'].split(';'))}\n")
        out.write("\n")
    return out.getvalue()
