"""CSV / JSON / text shaping for windows_tasks."""

from __future__ import annotations

import io

from windows_tasks import flags as _flags

COLUMNS = ["name", "task_path", "enabled", "hidden", "author", "reg_date",
           "registered", "last_run", "run_as", "run_level", "logon_type",
           "triggers", "command_line", "action_kinds", "guid", "tree_present",
           "registry_only", "xml_only", "source", "severity", "notable"]


def row(t) -> dict:
    r = {
        "name": t.name, "task_path": t.task_path,
        "enabled": "yes" if t.enabled else "no",
        "hidden": "yes" if t.hidden else "",
        "author": t.author, "reg_date": t.reg_date,
        "registered": t.registered, "last_run": t.last_run,
        "run_as": t.run_as, "run_level": t.run_level,
        "logon_type": t.logon_type,
        "triggers": " | ".join(t.triggers),
        "command_line": t.command_line,
        "action_kinds": t.action_kinds,
        "guid": t.guid,
        "tree_present": "yes" if t.tree_present else "no",
        "registry_only": "yes" if t.registry_only else "",
        "xml_only": "yes" if t.xml_only else "",
        "source": t.source,
        "notable": ";".join(t.notable),
    }
    r["severity"] = _flags.severity(t.notable)
    return r


def render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        state = []
        if r["enabled"] == "no":
            state.append("disabled")
        if r["hidden"] == "yes":
            state.append("hidden")
        s = f" ({', '.join(state)})" if state else ""
        out.write(f"{r['task_path']}{s}{mark}\n")
        if r["command_line"]:
            out.write(f"    run: {r['command_line']}\n")
        if r["run_as"]:
            out.write(f"    as:  {r['run_as']}"
                      f"{' / ' + r['run_level'] if r['run_level'] else ''}\n")
        if r["triggers"]:
            out.write(f"    when: {r['triggers']}\n")
        when = " ".join(x for x in (
            f"registered {r['registered']}" if r["registered"] else "",
            f"last-run {r['last_run']}" if r["last_run"] else "") if x)
        if when:
            out.write(f"    {when}\n")
        for n in r["notable"].split(";") if r["notable"] else []:
            out.write(f"    ! {n}\n")
    return out.getvalue()
