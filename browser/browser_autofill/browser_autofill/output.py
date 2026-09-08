"""CSV / JSON / text output for browser_autofill."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["last_used", "first_used", "browser", "profile", "kind", "name",
           "value", "detail", "count", "severity", "notable", "source_db"]

_SEV = {
    "sensitive field name": "high",
    "payment-card metadata": "medium",
    "contact details in a saved address": "medium",
    "email address in form history": "low",
    "phone number in form history": "low",
    "search-box / query field": "none",
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


def row(rec) -> dict:
    r = rec.row()
    r["severity"] = _severity(rec.notable)
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
        when = r["last_used"] or r["first_used"] or "(no time)"
        body = r["value"] or r["detail"]
        cnt = f"  x{r['count']}" if r["count"] else ""
        out.write(f"{when:<21} {r['browser']:<8} {r['kind']:<10} "
                  f"{r['name']} = {body}{cnt}{mark}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    return out.getvalue()
