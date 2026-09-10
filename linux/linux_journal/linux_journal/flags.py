"""Heuristic flags for a journal entry."""

from __future__ import annotations

import re

# PRIORITY: 0 emerg 1 alert 2 crit 3 err 4 warning 5 notice 6 info 7 debug
_PRIO_NAME = {"0": "emerg", "1": "alert", "2": "crit", "3": "err",
              "4": "warning", "5": "notice", "6": "info", "7": "debug"}

_WRITABLE = re.compile(r"^/(tmp|var/tmp|dev/shm|run/user/\d+|home/[^/]+|"
                       r"root)/")
_CRADLE = re.compile(r"\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?"
                     r"(bash|sh|python[0-9.]*|perl)\b|"
                     r"\bbase64\s+-d\b|\bpython[0-9.]*\s+-c\b", re.I)
_RECON = re.compile(r"\b(nmap|masscan|nc|ncat|netcat|socat|tcpdump|nikto|"
                    r"hydra|responder|impacket|crackmapexec|chisel|"
                    r"proxychains|mimikatz)\b", re.I)


def flag(e) -> list[str]:
    f = e.fields
    out: list[str] = []

    prio = f.get("PRIORITY", "")
    if prio in ("0", "1", "2", "3"):
        out.append(f"priority {_PRIO_NAME.get(prio, prio)}")

    unit = f.get("_SYSTEMD_UNIT", "") or f.get("UNIT", "")
    exe = f.get("_EXE", "")
    comm = f.get("_COMM", "")
    msg = f.get("MESSAGE", "")
    cmd = f.get("_CMDLINE", "")

    if exe and _WRITABLE.match(exe):
        out.append(f"process image in a user-writable path ({exe})")
    if unit.startswith("systemd-coredump") or \
            f.get("MESSAGE_ID", "") == "fc2e22bc6ee647b6b90729ab34a250b1":
        out.append(f"coredump recorded ({f.get('COREDUMP_COMM', comm)})")
    if _CRADLE.search(msg) or _CRADLE.search(cmd):
        out.append("download / decode cradle in the command or message")
    if _RECON.search(msg) or _RECON.search(cmd) or _RECON.search(comm):
        out.append("offensive / recon tool referenced")
    if comm == "sshd" and re.search(r"Failed password|Invalid user|"
                                    r"authentication failure", msg):
        out.append("SSH authentication failure")
    if comm == "sshd" and "Accepted" in msg:
        out.append("SSH login accepted")
    if comm in ("sudo", "su") and re.search(r"authentication failure|"
                                            r"incorrect password", msg, re.I):
        out.append(f"{comm} authentication failure")
    if f.get("_TRANSPORT", "") == "audit":
        out.append("kernel audit event via the journal")
    if re.search(r"segfault|general protection|traps:", msg):
        out.append("segfault / trap logged")
    if unit and unit.endswith(".service") and \
            f.get("JOB_RESULT", "") in ("failed", "timeout", "dependency"):
        out.append(f"unit job {f.get('JOB_RESULT')} ({unit})")
    return out


_SEV = {
    "priority emerg": "high", "priority alert": "high", "priority crit": "high",
    "priority err": "medium",
    "process image in a user-writable path": "high",
    "download / decode cradle": "high",
    "offensive / recon tool referenced": "high",
    "coredump recorded": "medium",
    "SSH authentication failure": "medium",
    "SSH login accepted": "low",
    "sudo authentication failure": "medium",
    "su authentication failure": "medium",
    "kernel audit event via the journal": "low",
    "segfault / trap logged": "medium",
    "unit job": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
