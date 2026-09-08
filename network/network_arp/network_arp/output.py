"""CSV / JSON / text output for network_arp."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["ip", "mac", "vendor", "hostnames", "first_seen", "last_seen",
           "observations", "sources", "ifaces", "kinds", "severity", "notable"]

_HIGH = ("overlapping in time", "MAC spoofing", "locally-administered")
_MED = ("claimed by", "bound to", "gratuitous ARP")


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _severity(notable: list) -> str:
    j = " ".join(notable)
    if any(k in j for k in _HIGH):
        return "high"
    if any(k in j for k in _MED):
        return "medium"
    return "none"


def row(b) -> dict:
    r = b.row()
    r["severity"] = _severity(b.notable)
    return r


def write_csv(rows, path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path) -> None:
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def render(rows, conflicts=None) -> str:
    out = io.StringIO()
    if conflicts:
        out.write("conflicts:\n")
        for c in conflicts:
            out.write(f"  ! {c}\n")
        out.write("\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        span = r["first_seen"] or "(no time)"
        if r["last_seen"] and r["last_seen"] != r["first_seen"]:
            span += f" .. {r['last_seen']}"
        host = f"  {r['hostnames']}" if r["hostnames"] else ""
        vend = f"  ({r['vendor']})" if r["vendor"] else ""
        out.write(f"{r['ip']:<16} {r['mac']}{vend}{host}{mark}\n")
        out.write(f"    {span}  via {r['sources']}  [{r['kinds']}]\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
        out.write("\n")
    return out.getvalue()
