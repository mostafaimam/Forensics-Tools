"""Heuristic flags for a package event (per-event + cross-event)."""

from __future__ import annotations

import re

_TOOLCHAIN = re.compile(
    r"^(gcc|g\+\+|cpp|clang|llvm|make|cmake|automake|autoconf|libtool|"
    r"build-essential|binutils|gdb|golang|rustc|cargo|nasm|yasm|"
    r"linux-headers|kernel-devel|kernel-headers|dkms|gcc-\d)")
_RECON = re.compile(
    r"^(nmap|masscan|netcat|ncat|socat|tcpdump|tshark|wireshark|hydra|"
    r"john|hashcat|medusa|nikto|sqlmap|aircrack-ng|responder|"
    r"bettercap|ettercap|impacket|crackmapexec|chisel|proxychains|"
    r"metasploit|msfconsole|empire|sliver|nuclei|gobuster|ffuf|"
    r"powersploit|mimikatz|evil-winrm|enum4linux)")
_TUNNEL = re.compile(r"^(openvpn|wireguard|tor|obfs4proxy|shadowsocks|"
                     r"stunnel|sshuttle|frp|ngrok|cloudflared|zerotier|"
                     r"tailscale)")
_ANTIFOR = re.compile(r"^(bleachbit|shred|secure-delete|wipe|nwipe|"
                      r"timeshift)")
_MANUAL_DEB = re.compile(r"\bdpkg\b.*\s-i\b|\bdpkg\s+--install\b|"
                         r"\b\.deb\b", re.I)


def flag(ev) -> list[str]:
    out: list[str] = []
    p = ev.package.lower()
    if _TOOLCHAIN.match(p):
        out.append("compiler / build toolchain installed")
    if _RECON.match(p):
        out.append(f"offensive / recon tool installed ({ev.package})")
    if _TUNNEL.match(p):
        out.append(f"tunnel / VPN client installed ({ev.package})")
    if _ANTIFOR.match(p):
        out.append(f"anti-forensic / wiping tool installed ({ev.package})")
    if ev.action == "downgrade":
        out.append(f"package downgraded ({ev.from_version or '?'} -> "
                   f"{ev.version or '?'})")
    if ev.action in ("install", "upgrade", "reinstall") and \
            _MANUAL_DEB.search(ev.command or ""):
        out.append("manual .deb install (out-of-repo package file)")
    if ev.command and re.search(r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(dpkg|apt|"
                                r"dnf|yum|rpm)", ev.command):
        out.append("package manager invoked from a download pipe")
    return out


def aggregate(events) -> list[str]:
    """Cross-event findings; also tags individual events."""
    from collections import defaultdict
    findings: list[str] = []

    # a package that was removed and later (re)installed
    seen_remove: dict[str, str] = {}
    for ev in sorted(events, key=lambda e: e.ts or ""):
        p = ev.package
        if ev.action in ("remove", "purge"):
            seen_remove[p] = ev.ts
        elif ev.action in ("install", "reinstall") and p in seen_remove:
            ev.notable.append("re-installed after an earlier removal")
            del seen_remove[p]

    # a burst of installs in one apt/dnf transaction with a shell in cmdline
    by_cmd = defaultdict(list)
    for ev in events:
        if ev.command:
            by_cmd[(ev.ts, ev.command)].append(ev)
    for (ts, cmd), evs in by_cmd.items():
        if re.search(r"(sh\s+-c|bash\s+-c|;|&&)\s", cmd) and len(evs) >= 1:
            findings.append(f"{ts or '?'}: package op inside a shell command "
                            f"- {cmd[:120]}")
    return findings


_SEV = {
    "offensive / recon tool": "high", "anti-forensic": "high",
    "manual .deb install": "medium", "package manager invoked from a download":
    "high", "compiler / build toolchain": "low", "tunnel / VPN client":
    "medium", "package downgraded": "medium",
    "re-installed after an earlier removal": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
