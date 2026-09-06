"""Unified job model and suspicious-entry heuristics."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_RULES = [
    (re.compile(r"\b(curl|wget|fetch)\b[^|;&]*\|\s*(sh|bash|python|perl|node)"),
     "downloads and pipes straight to an interpreter"),
    (re.compile(r"\b(curl|wget)\b.*\b(-o|-O|--output)\b.*;\s*(chmod|\./|sh |bash )"),
     "downloads a file then runs it"),
    (re.compile(r"base64\s+(-d|--decode)|\bb64decode\b|\batob\(|"
                r"FromBase64String|base64 -d"), "decodes a base64 payload"),
    (re.compile(r"\b(eval|exec)\s*\("), "eval/exec of a constructed string"),
    (re.compile(r"echo\s+[A-Za-z0-9+/]{40,}={0,2}\s*\|"),
     "pipes a long base64-looking blob"),
    (re.compile(r"/dev/tcp/|/dev/udp/"), "bash /dev/tcp reverse-shell primitive"),
    (re.compile(r"\bnc\b.*\s-e\b|\bncat\b.*\s-e\b|\bmkfifo\b.*\|\s*(nc|sh|bash)"),
     "netcat/named-pipe reverse shell"),
    (re.compile(r"\bbash\s+-i\b|\bsh\s+-i\b"), "interactive shell spawn"),
    (re.compile(r"(^|[\s=:])/tmp/|/dev/shm/|/var/tmp/|/run/shm/"),
     "runs a command from a world-writable directory"),
    (re.compile(r"\bpython[23]?\b\s+-c\b|\bperl\b\s+-e\b|\bruby\b\s+-e\b"),
     "inline interpreter one-liner"),
    (re.compile(r"authorized_keys"), "touches an SSH authorized_keys file"),
    (re.compile(r"chmod\s+([0-7]*7[0-7]{2}|\+s|u\+s|[0-7]*[4-7][0-7]{3})"),
     "sets world-writable or setuid permissions"),
    (re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*~?/?\.bash_history"),
     "clears or disables shell history"),
    (re.compile(r"(^|/)\.[A-Za-z0-9_-]+\b.*(\.sh|\.py|\.pl|\.elf|\.bin)?\s*$"),
     "invokes a hidden (dot-prefixed) file"),
    (re.compile(r"\b(xmrig|minerd|cpuminer|stratum\+tcp)\b"), "cryptominer keyword"),
    (re.compile(r"\b0\.0\.0\.0\b|\b\d{1,3}(\.\d{1,3}){3}:\d+\b"),
     "hard-coded IP:port"),
]

_SUSPECT_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
                 "/run/user/", "/root/.", "/home/")


@dataclass
class Job:
    source: str            # crontab | cron.d | system-crontab | user-crontab |
    #                        run-parts | anacron | at | systemd-timer
    run_as: str = ""
    schedule_raw: str = ""
    schedule_desc: str = ""
    command: str = ""
    env_path: str = ""
    enabled: str = ""
    reboot: bool = False
    notable: list = field(default_factory=list)
    file: str = ""
    line_no: int = 0
    error: str = ""

    def flag(self) -> None:
        self.notable = notable_reasons(self)


def notable_reasons(job: Job) -> list[str]:
    reasons: list[str] = []
    cmd = job.command or ""
    if job.reboot or job.schedule_raw.startswith(("OnBootSec", "@period")) \
            or "OnBootSec" in job.schedule_raw:
        reasons.append("persistence: fires at boot / anacron start")
    low = cmd.lower()
    for rx, why in _RULES:
        if rx.search(cmd) or rx.search(low):
            if why not in reasons:
                reasons.append(why)
    # PATH pointing somewhere writable
    if job.env_path:
        for d in job.env_path.split(":"):
            if d and d.startswith(("/tmp", "/home", "/var/tmp", "/dev/shm", ".")):
                reasons.append(f"PATH includes a writable/unusual dir: {d}")
                break
    # program path itself
    first = cmd.strip().split()[0] if cmd.strip() else ""
    first = first.strip('"\'')
    if first.startswith(_SUSPECT_DIRS):
        reasons.append(f"program lives under a user-writable / home dir: {first}")
    if first.startswith(("./", "../", "~")):
        reasons.append("relative or home-relative program path")
    return reasons
