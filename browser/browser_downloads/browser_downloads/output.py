"""CSV / JSON / text output for browser_downloads."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from browser_downloads import flags as _flags

COLUMNS = ["start_time", "end_time", "browser", "profile", "source",
           "filename", "target_path", "url", "referrer", "received_bytes",
           "total_bytes", "state", "danger", "interrupt", "mime", "opened",
           "on_disk", "disk_size", "sha256", "zone_id", "zone_host",
           "zone_referrer", "severity", "notable"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(d) -> dict:
    r = d.row()
    r["severity"] = _flags.severity(d.notable)
    return r


def write_csv(rows, path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path) -> None:
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        when = r["start_time"] or r["end_time"] or "(no time)"
        size = ""
        if r["received_bytes"]:
            size = f"  {r['received_bytes']:,}"
            if r["total_bytes"] and r["total_bytes"] != r["received_bytes"]:
                size += f"/{r['total_bytes']:,}"
            size += " B"
        disk = f"  [disk: {r['on_disk']}]" if r["on_disk"] else ""
        out.write(f"{when:<21} {r['browser'] or '-':<8} "
                  f"{r['filename'] or '(unnamed)'}{size}{disk}{mark}\n")
        if r["url"]:
            out.write(f"    from {r['url']}\n")
        if r["referrer"]:
            out.write(f"    ref  {r['referrer']}\n")
        if r["target_path"]:
            out.write(f"    ->   {r['target_path']}\n")
        if r["sha256"]:
            out.write(f"    sha256 {r['sha256']}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
        out.write("\n")
    return out.getvalue()
