"""CSV / JSON / text output for linux_units."""

from __future__ import annotations

import io

from linux_units import flags as _flags

COLUMNS = ["name", "scope", "type", "description", "exec_start", "user",
           "wanted_by", "enabled", "enabled_via", "restart",
           "remain_after_exit", "has_install", "drop_ins", "unit_file",
           "mtime", "severity", "notable"]


def row(u) -> dict:
    r = u.row()
    r["severity"] = _flags.severity(u.notable)
    return r


def render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        en = " (enabled)" if r["enabled"] == "yes" else (
            " (masked)" if r["enabled"] == "masked" else "")
        out.write(f"{r['name']}{en}{mark}\n")
        if r["description"]:
            out.write(f"    {r['description']}\n")
        if r["exec_start"]:
            out.write(f"    ExecStart: {r['exec_start']}\n")
        if r["user"]:
            out.write(f"    User: {r['user']}   Restart: {r['restart'] or '-'}\n")
        if r["drop_ins"]:
            out.write(f"    drop-ins: {r['drop_ins']}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
        out.write("\n")
    return out.getvalue()
