"""CSV / JSON / text output for network_flows."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from network_flows import flags as _flags

COLUMNS = ["first_seen", "last_seen", "duration_s", "proto", "client",
           "server", "server_port", "flows", "bytes", "packets",
           "bytes_c2s", "bytes_s2c", "tcp_flags", "src_as", "dst_as",
           "exporters", "severity", "notable"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(c) -> dict:
    r = c.row()
    r["severity"] = _flags.severity(c.notable)
    return r


def write_csv(rows, path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path) -> None:
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def _sz(n: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}P"


def render(rows, res=None) -> str:
    out = io.StringIO()
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        when = r["first_seen"] or "(no time)"
        out.write(f"{when:<21} {r['proto']:<5} "
                  f"{r['client']} -> {r['server']}:{r['server_port']}  "
                  f"{_sz(r['bytes'])}  {r['packets']} pkt  "
                  f"{r['duration_s']}s  {r['tcp_flags']}{mark}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    if res is not None and res.talkers:
        out.write("\ntop talkers (bytes):\n")
        for ip, by in res.talkers[:10]:
            out.write(f"  {_sz(by):>9}  {ip}\n")
        out.write("\ntop server ports (bytes):\n")
        for proto, port, n, by in res.ports[:10]:
            out.write(f"  {_sz(by):>9}  {proto}/{port}  ({n} conversations)\n")
    return out.getvalue()
