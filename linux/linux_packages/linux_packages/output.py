"""CSV / JSON / text output for linux_packages."""

from __future__ import annotations

import io

from linux_packages import flags as _flags

COLUMNS = ["ts", "action", "package", "version", "from_version", "arch",
           "source", "requested_by", "command", "log_file", "severity",
           "notable"]


def row(ev) -> dict:
    r = ev.row()
    r["severity"] = _flags.severity(ev.notable)
    return r


def render(rows, findings=None) -> str:
    out = io.StringIO()
    if findings:
        out.write("findings:\n")
        for f in findings:
            out.write(f"  * {f}\n")
        out.write("\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        when = r["ts"] or "(no time)"
        vers = r["version"] or r["from_version"]
        chg = (f"{r['from_version']} -> {r['version']}"
               if r["from_version"] and r["version"]
               and r["from_version"] != r["version"] else vers)
        out.write(f"{when:<21} {r['source']:<5} {r['action']:<10} "
                  f"{r['package']} {chg}{mark}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    return out.getvalue()
