"""CSV / JSON / text shaping for linux_audit."""

from __future__ import annotations

import io

from linux_audit import flags as _flags

COLUMNS = ["ts", "serial", "action", "success", "syscall", "exe", "comm",
           "command", "cwd", "paths", "key", "uid", "auid", "pid", "ppid",
           "ses", "actor", "addr", "types", "summary", "severity", "log_file",
           "notable"]


def row(ev) -> dict:
    r = ev.row()
    r["severity"] = _flags.severity(ev.notable)
    return r


def render(rows, actions=None) -> str:
    out = io.StringIO()
    if actions:
        tally = ", ".join(f"{k}:{v}" for k, v in sorted(actions.items()))
        out.write(f"events by action: {tally}\n\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        who = r["actor"] or r["auid"] or r["uid"] or "-"
        out.write(f"{r['ts'] or '(no time)':<28} {r['action']:<15} "
                  f"{who:<10} {r['summary']}{mark}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    return out.getvalue()
