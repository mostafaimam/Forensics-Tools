"""Heuristic flags for a systemd unit."""

from __future__ import annotations

import re
import shlex

_WRITABLE = re.compile(
    r"(^|[ =])(/tmp/|/var/tmp/|/dev/shm/|/run/user/|/home/|/root/\.|"
    r"/var/www/|/srv/|/opt/[^/]+/data/)", re.I)
_INLINE_SHELL = re.compile(
    r"\b(sh|bash|dash|zsh|ksh)\b\s+-\w*c\b|"
    r"\b(curl|wget)\b[^|]*\|\s*(sh|bash)|"
    r"\bpython[0-9.]*\b\s+-c\b|\bperl\b\s+-e\b|\beval\b", re.I)
_ENCODED = re.compile(r"base64\s+-d|--decode|\bfrombase64|\\x[0-9a-f]{2}"
                      r"|echo\s+[A-Za-z0-9+/]{40,}={0,2}", re.I)
_SUSPECT_NAMES = re.compile(
    r"^(update|system|systemd-|kernel|dbus|network|watchdog|helper|service"
    r"|sync|daemon)[a-z0-9_-]*\.(service|timer)$", re.I)
_STD_UNIT_DIRS = ("usr/lib/systemd", "lib/systemd")


def _bin_of(exec_line: str) -> str:
    line = exec_line.lstrip("-@+!:")
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    return parts[0] if parts else ""


def flag(u, root) -> list[str]:
    out: list[str] = []
    execs = u.exec_start + u.exec_start_pre
    joined = " ".join(execs)

    if u.masked:
        out.append("unit is masked (-> /dev/null)")
        return out

    for e in execs:
        b = _bin_of(e)
        if _WRITABLE.search(" " + b) or _WRITABLE.search(" " + e):
            out.append(f"ExecStart in a user-writable / temp path ({b})")
            break
    if _INLINE_SHELL.search(joined):
        out.append("ExecStart runs an inline shell / download cradle")
    if _ENCODED.search(joined):
        out.append("ExecStart contains an encoded payload")

    # binary lives in a writable dir even if not temp
    for e in execs:
        b = _bin_of(e)
        if b.startswith(("/home/", "/root/", "/tmp/")) and \
                "ExecStart in a user-writable" not in " ".join(out):
            out.append(f"ExecStart binary under a home directory ({b})")
            break

    # persistence shape: aggressive respawner
    if u.name.endswith(".service"):
        rl = u.restart.lower()
        rs_txt = u.restart_sec.rstrip("s")
        rs = None
        try:
            rs = float(rs_txt) if rs_txt else None
        except ValueError:
            rs = None
        if rl == "always" and (rs is None or rs <= 5):
            out.append(f"Restart=always with a "
                       + (f"tight RestartSec ({u.restart_sec})" if rs is not None
                          else "default (100ms) RestartSec"))
        elif rl in ("on-failure", "on-abnormal") and rs is not None and rs <= 1:
            out.append(f"Restart={u.restart} with RestartSec={u.restart_sec}")

    # enabled but no [Install] -> manually symlinked
    if u.enabled and not u.has_install:
        out.append("enabled via a .wants symlink but has no [Install] section")

    # a unit shipped under /etc that shadows a vendor unit name pattern
    if u.unit_file.startswith("etc/systemd") and _SUSPECT_NAMES.match(u.name) \
            and not u.description:
        out.append("system-looking name, no description, in /etc "
                   "(possible masquerade)")

    # RemainAfterExit oneshot that just runs a command (fire-and-forget)
    if u.remain_after_exit and execs and u.restart.lower() in ("", "no") \
            and _INLINE_SHELL.search(joined):
        out.append("oneshot RemainAfterExit running an inline command")

    if u.user == "root" and any(
            _bin_of(e).startswith(("/home/", "/tmp/", "/var/tmp/",
                                   "/dev/shm/")) for e in execs):
        out.append("runs as root from a writable path")

    return out


_SEV = {
    "ExecStart in a user-writable": 3, "inline shell / download cradle": 3,
    "encoded payload": 3, "runs as root from a writable path": 3,
    "ExecStart binary under a home": 3,
    "system-looking name, no description": 3,
    "Restart=": 2, "no [Install] section": 2,
    "oneshot RemainAfterExit running": 2, "unit is masked": 1,
}


def severity(notable) -> str:
    top = 0
    for n in notable:
        for k, v in _SEV.items():
            if k in n:
                top = max(top, v)
    return {0: "none", 1: "low", 2: "medium", 3: "high"}[top]
