"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["risk", "browser", "profile", "name", "ext_id", "version",
           "enabled", "install_source", "from_webstore", "signed_state",
           "install_time", "update_url", "host_permissions",
           "api_permissions", "content_scripts", "background", "notable",
           "path", "source_file"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(ext) -> dict:
    return ext.row()


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
        head = f"[{r['risk']}] {r['name'] or '(no name)'}  {r['version']}"
        if not r["enabled"]:
            head += "  (disabled)"
        out.write(head + "\n")
        out.write(f"    {r['browser']} / {r['profile']}   id {r['ext_id']}\n")
        out.write(f"    source: {r['install_source']}"
                  + (f"   signed: {r['signed_state']}" if r["signed_state"]
                     else "")
                  + (f"   installed {r['install_time']}"
                     if r["install_time"] else "") + "\n")
        if r["host_permissions"]:
            out.write(f"    hosts:  {r['host_permissions']}\n")
        if r["api_permissions"]:
            out.write(f"    api:    {r['api_permissions']}\n")
        if r["update_url"]:
            out.write(f"    update: {r['update_url']}\n")
        if r["notable"]:
            out.write(f"    !       {', '.join(r['notable'].split(';'))}\n")
        out.write("\n")
    return out.getvalue()
