"""CSV / JSON / text output for browser_logins."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["date_last_used", "date_created", "date_password_changed",
           "browser", "profile", "host", "origin", "realm", "username",
           "username_field", "times_used", "blacklisted", "has_password",
           "scheme", "severity", "notable", "source_db"]

_SEV = {
    "credential stored for an http": "medium",
    "credential for a bare-IP origin": "medium",
    "store protected by a Primary Password": "low",
    "password saved with no username": "low",
    "credential for a non-FQDN host": "low",
    "site excluded from saving": "none",
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


def row(lg) -> dict:
    r = lg.row()
    r["severity"] = _severity(lg.notable)
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
        when = r["date_last_used"] or r["date_created"] or "(no time)"
        if r["blacklisted"]:
            out.write(f"{when:<21} {r['browser']:<8} NEVER-SAVE  "
                      f"{r['host'] or r['origin']}{mark}\n")
            continue
        u = r["username"] or "(no username)"
        cnt = f"  x{r['times_used']}" if r["times_used"] else ""
        pw = "  [pw blob]" if r["has_password"] else ""
        out.write(f"{when:<21} {r['browser']:<8} {r['host']:<30} "
                  f"{u}{pw}{cnt}{mark}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    return out.getvalue()
