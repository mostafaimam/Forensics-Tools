"""Manifest CSV / JSON + text render for network_dns."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from network_dns import flags as _flags

COLUMNS = ["qname", "sources", "qtypes", "first_seen", "last_seen", "queries",
           "responses", "nxdomain", "servfail", "resolvers", "clients", "ips",
           "cnames", "ttl_min", "ttl_max", "txt_max_len", "hosts_override",
           "severity", "notable"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(rec) -> dict:
    r = rec.row()
    r["severity"] = _flags.severity(rec.notable)
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
        when = r["first_seen"] or "(no time)"
        out.write(f"{when:<21} {r['qname']}  "
                  f"{r['qtypes'] or '?'}{mark}\n")
        detail = []
        if r["ips"]:
            detail.append(r["ips"])
        if r["cnames"]:
            detail.append("CNAME " + r["cnames"])
        if r["hosts_override"]:
            detail.append("hosts=" + r["hosts_override"])
        if r["nxdomain"]:
            detail.append(f"NXDOMAIN x{r['nxdomain']}")
        if detail:
            out.write("    " + "  ".join(detail) + "\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
        out.write("\n")
    return out.getvalue()
