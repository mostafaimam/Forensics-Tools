"""CSV / JSON / text output for browser_bookmarks."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["date_added", "date_modified", "date_last_used", "browser",
           "profile", "folder", "title", "url", "guid", "source",
           "severity", "notable"]

_SEV = {
    "bookmarklet (javascript": "medium",
    "bookmark to a local file": "low",
    "bookmark to an FTP resource": "low",
    "bookmark to a raw IP address": "medium",
    "bookmark to a non-standard port": "low",
    "bookmark to a browser-internal page": "low",
    "only present in Bookmarks.bak": "medium",
}


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _severity(notable: list) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top


def row(bm) -> dict:
    r = bm.row()
    r["severity"] = _severity(bm.notable)
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
        when = r["date_added"] or "(no date)"
        src = "" if r["source"] in ("bookmarks", "places") \
            else f"  <{r['source']}>"
        out.write(f"{when:<21} {r['browser']:<8} {r['folder']}/"
                  f"{r['title'] or '(untitled)'}{src}{mark}\n")
        if r["url"]:
            out.write(f"    {r['url']}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    return out.getvalue()
