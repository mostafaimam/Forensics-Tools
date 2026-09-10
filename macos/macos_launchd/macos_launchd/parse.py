"""Parse a single launchd job plist."""

from __future__ import annotations

import os
import plistlib
import stat
from dataclasses import dataclass, field


@dataclass
class Job:
    scope: str                 # system-daemon | system-agent | user-agent | apple
    label: str
    filename: str
    program: str
    arguments: list
    command_line: str
    run_as: str
    disabled: bool
    run_at_load: bool
    keep_alive: str            # "" | "true" | a summary of the dict
    triggers: list
    env: dict
    stdout_path: str
    stderr_path: str
    mach_services: list
    world_writable: bool
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "scope": self.scope, "label": self.label,
            "filename": self.filename, "program": self.program,
            "command_line": self.command_line, "run_as": self.run_as,
            "disabled": "yes" if self.disabled else "",
            "run_at_load": "yes" if self.run_at_load else "",
            "keep_alive": self.keep_alive,
            "triggers": " | ".join(self.triggers),
            "env": ";".join(f"{k}={v}" for k, v in self.env.items()),
            "stdout": self.stdout_path, "stderr": self.stderr_path,
            "mach_services": ",".join(self.mach_services),
            "world_writable": "yes" if self.world_writable else "",
            "source": self.source, "notable": ";".join(self.notable),
        }


_CAL_KEYS = {"Minute": "min", "Hour": "hr", "Day": "day",
             "Weekday": "wday", "Month": "mon"}


def _cal(entry) -> str:
    if isinstance(entry, dict):
        return "at " + " ".join(f"{_CAL_KEYS.get(k, k)}={v}"
                                for k, v in entry.items())
    if isinstance(entry, list):
        return "; ".join(_cal(e) for e in entry)
    return "on a calendar schedule"


def _scope_for(rel_posix: str) -> str:
    low = rel_posix.lower()
    if low.startswith("system/library/"):
        return "apple"
    if low.startswith(("users/", "home/")) or "/users/" in "/" + low:
        return "user-agent"
    if "launchdaemons" in low:
        return "system-daemon"
    return "system-agent"


def parse_bytes(data: bytes, source: str, rel_posix: str,
                st_mode: int | None = None) -> Job | None:
    try:
        d = plistlib.loads(data)
    except Exception:                            # noqa: BLE001
        return None
    if not isinstance(d, dict):
        return None

    prog = str(d.get("Program", "") or "")
    args = d.get("ProgramArguments")
    args = [str(a) for a in args] if isinstance(args, list) else []
    if not prog and args:
        prog = args[0]
    cmd = " ".join(args) if args else prog

    triggers = []
    if d.get("RunAtLoad"):
        triggers.append("at load")
    if d.get("StartOnMount"):
        triggers.append("on mount")
    si = d.get("StartInterval")
    if si:
        triggers.append(f"every {si}s")
    if "StartCalendarInterval" in d:
        triggers.append(_cal(d["StartCalendarInterval"]))
    wp = d.get("WatchPaths")
    if wp:
        triggers.append("watch " + ", ".join(wp[:4] if isinstance(wp, list)
                                              else [str(wp)]))
    qd = d.get("QueueDirectories")
    if qd:
        triggers.append("queue " + ", ".join(qd[:3] if isinstance(qd, list)
                                              else [str(qd)]))

    ka = d.get("KeepAlive")
    if ka is True:
        keep_alive = "true"
        triggers.append("keepalive")
    elif isinstance(ka, dict):
        keep_alive = ", ".join(f"{k}={v}" for k, v in ka.items())
        triggers.append("keepalive (" + keep_alive + ")")
    else:
        keep_alive = ""

    env = {str(k): str(v) for k, v in
           (d.get("EnvironmentVariables") or {}).items()}
    ms = list((d.get("MachServices") or {}).keys())

    ww = bool(st_mode is not None and st_mode & (stat.S_IWGRP | stat.S_IWOTH)
              and os.name != "nt")

    return Job(
        scope=_scope_for(rel_posix),
        label=str(d.get("Label", "") or ""),
        filename=rel_posix.rsplit("/", 1)[-1],
        program=prog, arguments=args, command_line=cmd,
        run_as=str(d.get("UserName", "") or ""),
        disabled=bool(d.get("Disabled")),
        run_at_load=bool(d.get("RunAtLoad")),
        keep_alive=keep_alive, triggers=triggers, env=env,
        stdout_path=str(d.get("StandardOutPath", "") or ""),
        stderr_path=str(d.get("StandardErrorPath", "") or ""),
        mach_services=ms, world_writable=ww, source=source)
