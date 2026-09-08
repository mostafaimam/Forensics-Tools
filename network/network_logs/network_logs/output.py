"""CSV / JSON / text output for network_logs."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from network_logs import flags as _flags

COLUMNS = ["time", "fmt", "action", "proto", "src", "sport", "dst", "dport",
           "bytes", "direction", "iface", "rule", "signature", "severity",
           "host", "user", "message", "sev_flag", "notable"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(ev) -> dict:
    r = ev.row()
    r["sev_flag"] = _flags.severity(ev.notable)
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
        mark = f"  [{r['sev_flag']}]" if r["sev_flag"] != "none" else ""
        when = r["time"] or "(no time)"
        s = f"{r['src']}:{r['sport']}" if r["sport"] else r["src"]
        d = f"{r['dst']}:{r['dport']}" if r["dport"] else r["dst"]
        out.write(f"{when:<21} {r['fmt']:<9} {r['action']:<6} "
                  f"{r['proto']:<5} {s} -> {d}{mark}\n")
        extra = r["signature"] or r["message"]
        if extra:
            out.write(f"    {extra[:160]}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    return out.getvalue()
