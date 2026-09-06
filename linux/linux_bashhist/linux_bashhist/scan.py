"""Final entry model and attacker-activity heuristics."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_RULES = [
    (re.compile(r"\b(curl|wget|fetch)\b[^|;&`$]*\|\s*(sh|bash|python[23]?|perl|"
                r"ruby|node)\b"), "pipes a download straight into an interpreter"),
    (re.compile(r"\b(curl|wget)\b.*-[oO]\b"), "downloads a file to disk"),
    (re.compile(r"/dev/tcp/|/dev/udp/"), "bash /dev/tcp network primitive"),
    (re.compile(r"\bnc\b[^|\n]*\s-[a-z]*e|\bncat\b[^|\n]*\s-[a-z]*e|"
                r"\bmkfifo\b.*\|\s*(nc|ncat|sh|bash)|socat\b.*exec"),
     "reverse / bind shell"),
    (re.compile(r"\b(bash|sh|python[23]?)\b\s+-\S*i\b.*(>&|0>&1|/dev/tcp)"),
     "interactive shell redirected to a socket"),
    (re.compile(r"base64\s+(-d|--decode)|\bb64decode\b|openssl\s+enc\s+-d|"
                r"\|\s*base64\s+-d|xxd\s+-r"), "decodes an encoded payload"),
    (re.compile(r"\becho\s+[A-Za-z0-9+/]{40,}={0,2}\b"),
     "long base64-looking literal"),
    (re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|export\s+HISTFILE=/dev/null|"
                r">\s*~?/?\.(bash|zsh)_history|\bset\s+\+o\s+history|"
                r"\bHISTSIZE=0\b|\brm\b\s+-\S*\s*~?/?\.(bash|zsh)_history"),
     "disables or wipes shell history"),
    (re.compile(r"\b(shred|wipe)\b|\brm\b\s+-\S*f\S*\s+/var/log|"
                r">\s*/var/log/\S+|truncate\s+-s\s*0\s+/var/log|"
                r"\bjournalctl\b.*--vacuum"), "tampers with system logs"),
    (re.compile(r"chattr\s+[+-][aiu]"), "sets immutable/append-only file flags"),
    (re.compile(r"\b(chmod|chown)\b.*(4[0-7]{3}|\+s|u\+s)|cp\b.*/bin/(ba)?sh\b.*"
                r";\s*chmod"), "creates a setuid binary"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)\b|/etc/sudoers\.d/|"
                r"\becho\b.*>>\s*/etc/(passwd|sudoers)"),
     "touches passwd / shadow / sudoers"),
    (re.compile(r"\.ssh/authorized_keys|\becho\b.*ssh-(rsa|ed25519|dss)"),
     "adds or edits an SSH authorized_keys entry"),
    (re.compile(r"\b(id|whoami|uname\s+-a|hostname|w|last|lastlog|cat\s+/etc/"
                r"(passwd|os-release)|sudo\s+-l|getcap|crontab\s+-l)\b"),
     "recon / enumeration command"),
    (re.compile(r"\b(nmap|masscan|zmap|hydra|medusa|hashcat|john|responder|"
                r"impacket-\w+|crackmapexec|nxc|evil-winrm)\b"),
     "offensive-tooling keyword"),
    (re.compile(r"\b(xmrig|minerd|cpuminer|nicehash)\b|stratum\+tcp://"),
     "cryptominer keyword"),
    (re.compile(r"\bcrontab\b\s+-|>\s*/etc/cron|/etc/cron\.d/|systemctl\s+"
                r"(enable|--now)\b|\bat\s+now\b"), "installs persistence"),
    (re.compile(r"\bscp\b|\brsync\b.*::|\bftp\b|\btftp\b|\bnc\b.*<\s|"
                r"curl\b.*(-T|--upload-file|-F\b)"), "possible data exfiltration"),
    (re.compile(r"\bdd\b\s+if=/dev/(sd|nvme|mmcblk|zero|urandom)"),
     "raw disk read/write"),
    (re.compile(r"\bpkill\b|\bkillall\b.*(auditd|rsyslog|syslog|falcon|"
                r"osquery|filebeat|auoms|wazuh)"), "kills a security agent"),
]

_RECON_CAT = "recon / enumeration command"


@dataclass
class Entry:
    user: str = ""
    shell: str = ""
    timestamp: object = None
    command: str = ""
    notable: list = field(default_factory=list)
    note: str = ""
    source_file: str = ""
    line_no: int = 0

    def flag(self) -> None:
        self.notable = notable_reasons(self.command)


def notable_reasons(command: str) -> list[str]:
    cmd = command or ""
    reasons: list[str] = []
    for rx, why in _RULES:
        if rx.search(cmd):
            if why not in reasons:
                reasons.append(why)
    # a single recon command is low signal; keep it only if it is the sole flag
    if reasons == [_RECON_CAT] and len(cmd.split("\n")) == 1 and ";" not in cmd \
            and "&&" not in cmd:
        pass  # still report, but callers can filter with --min-flags
    return reasons
