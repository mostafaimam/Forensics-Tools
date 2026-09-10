"""CSV / JSON / text shaping for linux_containers."""

from __future__ import annotations

import io

from linux_containers import flags as _flags

COLUMNS = ["engine", "id", "name", "image", "image_id", "state", "created",
           "started_at", "finished_at", "exit_code", "entrypoint", "command",
           "env", "mounts", "ports", "privileged", "cap_add", "security_opt",
           "network_mode", "pid_mode", "ipc_mode", "user", "restart_policy",
           "labels", "log_file", "source", "severity", "notable"]


def row(c) -> dict:
    r = c.row()
    r["severity"] = _flags.severity(c.notable)
    return r


def render(rows, engines=None) -> str:
    out = io.StringIO()
    if engines:
        tally = ", ".join(f"{k}:{v}" for k, v in sorted(engines.items()))
        out.write(f"containers by engine: {tally}\n\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        life = r["state"]
        if r["exit_code"] != "":
            life += f" (exit {r['exit_code']})"
        out.write(f"{r['engine']:<10} {r['name'] or r['id']:<24} "
                  f"{r['image']:<30} {life}{mark}\n")
        cmd = (r["entrypoint"] + " " + r["command"]).strip()
        if cmd:
            out.write(f"    cmd: {cmd}\n")
        if r["mounts"]:
            out.write(f"    mounts: {r['mounts']}\n")
        for n in r["notable"].split(";") if r["notable"] else []:
            out.write(f"    ! {n}\n")
    return out.getvalue()
