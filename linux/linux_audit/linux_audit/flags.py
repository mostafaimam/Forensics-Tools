"""Heuristic flags for an assembled audit event."""

from __future__ import annotations

import re

_WRITABLE = re.compile(r"^/(tmp|var/tmp|dev/shm|run/user/\d+|home/[^/]+|root)/")
_RECON = re.compile(r"\b(nmap|masscan|nc|ncat|netcat|socat|tcpdump|nikto|"
                    r"hydra|john|hashcat|responder|impacket|crackmapexec|"
                    r"chisel|proxychains|mimikatz|linpeas|pspy)\b", re.I)
_CRADLE = re.compile(r"\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?"
                     r"(bash|sh|python[0-9.]*|perl)\b|"
                     r"\bbase64\s+-d\b|\bpython[0-9.]*\s+-c\b", re.I)
_SENSITIVE_PATH = re.compile(r"/etc/(shadow|gshadow|sudoers|passwd|"
                             r"ssh/sshd_config|pam\.d/|audit/)")
_AUID_UNSET = {"4294967295", "-1", "unset"}


def flag(ev) -> list[str]:
    out: list[str] = []
    cmd = ev.command or ""
    exe = ev.exe or ""

    if ev.action == "execve" and exe and _WRITABLE.match(exe):
        out.append(f"executed from a user-writable path ({exe})")
    if _RECON.search(cmd) or _RECON.search(exe):
        out.append("offensive / recon tool executed")
    if _CRADLE.search(cmd):
        out.append("download / decode cradle in the command")
    if ev.success == "no" and ev.action == "execve":
        out.append("execve denied / failed")

    # privilege context: a daemon-spawned (no login uid) root execve of a
    # shell / interpreter is worth a look; plain sudo (auid set) is not.
    if ev.action == "execve" and ev.uid == "0" and ev.auid in _AUID_UNSET \
            and (ev.comm in ("sh", "bash", "dash", "zsh", "python", "python3",
                             "perl", "nc", "ncat")
                 or "/tmp/" in ev.exe or "/dev/shm/" in ev.exe):
        out.append("root shell / interpreter with no login uid")
    if ev.action == "user-cmd" and (ev.result in ("failed", "0")):
        out.append("failed sudo / privileged command")
    if ev.action == "auth" and ev.result in ("failed", "0"):
        out.append("authentication failure")
    if ev.action == "account-change":
        out.append(f"account / group change ({ev.key or ','.join(ev.types)})")
    if ev.action == "audit-config":
        out.append("audit rule set changed (possible tampering)")
    if ev.action == "selinux-denial":
        out.append("SELinux access denial")
    if ev.action == "anomaly":
        out.append(f"kernel anomaly record ({','.join(ev.types)})")

    for p in ev.paths:
        if _SENSITIVE_PATH.search(p):
            out.append(f"touched a sensitive file ({p})")
            break

    if ev.action == "network" and ev.addr and _public_ip(ev.addr):
        out.append(f"outbound connection to {ev.addr}")

    if "init_module" in ev.syscall or "finit_module" in ev.syscall:
        out.append("kernel module loaded")
    if ev.syscall == "ptrace":
        out.append("ptrace call (debugger / injection)")

    # de-dup, keep order
    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


def _public_ip(addr: str) -> bool:
    ip = addr.split(":")[0].strip("[]")
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", ip)
    if not m:
        return False
    a, b = int(m.group(1)), int(m.group(2))
    if a in (10, 127, 0) or (a == 192 and b == 168) or \
            (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254):
        return False
    return True


_SEV = {
    "executed from a user-writable path": "high",
    "offensive / recon tool executed": "high",
    "download / decode cradle in the command": "high",
    "root shell / interpreter with no login uid": "high",
    "audit rule set changed": "high",
    "kernel module loaded": "high",
    "touched a sensitive file": "high",
    "outbound connection to": "medium",
    "ptrace call": "medium",
    "failed sudo / privileged command": "medium",
    "authentication failure": "medium",
    "account / group change": "medium",
    "SELinux access denial": "medium",
    "kernel anomaly record": "medium",
    "execve denied / failed": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
