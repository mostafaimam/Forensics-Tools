"""CSV / JSON / text output for browser_sessions."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["last_accessed", "browser", "profile", "source", "window", "index",
           "pinned", "group", "closed", "current_url", "current_title",
           "entry_count", "history", "has_formdata", "severity", "notable"]

_SEV = {
    "restored form data preserved": "medium",
    "tab left on a sign-in / auth page": "medium",
    "tab pointing at a local file": "low",
    "tab to a raw IP address": "medium",
    "recently-closed tab retained": "low",
}


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _severity(notable):
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top


def row(t) -> dict:
    r = t.row()
    r["severity"] = _severity(t.notable)
    return r


def write_csv(rows, path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path) -> None:
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def render(rows, findings=None) -> str:
    out = io.StringIO()
    if findings:
        out.write("findings:\n")
        for f in findings:
            out.write(f"  * {f}\n")
        out.write("\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        tags = []
        if r["pinned"]:
            tags.append("pinned")
        if r["closed"]:
            tags.append("closed")
        if r["has_formdata"]:
            tags.append("formdata")
        tag = f"  ({', '.join(tags)})" if tags else ""
        when = r["last_accessed"] or ""
        out.write(f"{when:<21} {r['browser']:<8} {r['window']}/tab "
                  f"{r['index']}{tag}{mark}\n")
        out.write(f"    {r['current_title'] or '(no title)'}\n")
        out.write(f"    {r['current_url']}\n")
        if r["entry_count"] > 1 and r["history"]:
            out.write(f"    [{r['entry_count']} history entries]  "
                      f"{r['history']}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
        out.write("\n")
    return out.getvalue()
