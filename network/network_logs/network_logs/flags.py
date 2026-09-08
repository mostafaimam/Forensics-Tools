"""Per-event and aggregate flags for normalised network-log events."""

from __future__ import annotations

import ipaddress
import re

_SUSPICIOUS_PORTS = {1337, 3333, 4444, 4445, 5555, 6666, 6667, 9001, 12345,
                     31337, 54321, 8081, 1080}
_CREDS_IN_URL = re.compile(r"://[^/\s:@]+:[^/\s@]+@")
_RAW_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def flag(ev) -> list[str]:
    out: list[str] = []
    blocked = ev.action in ("deny", "drop", "reject")

    if ev.action == "alert":
        sev = ev.severity or "?"
        out.append(f"IDS alert (severity {sev}): {ev.signature or ev.message}")

    if blocked and _public(ev.src) and (ev.direction == "in"
                                        or (ev.dport and ev.dport < 1024)):
        out.append("blocked inbound connection from a public address")

    if ev.dport in _SUSPICIOUS_PORTS and not blocked:
        out.append(f"connection to a commonly-abused port ({ev.dport})")

    if ev.signature and _CREDS_IN_URL.search(ev.signature):
        out.append("credentials embedded in a proxied URL")

    if ev.host and _RAW_IP_HOST.match(ev.host) and _public(ev.host):
        out.append("request to a raw-IP host (no domain)")

    if ev.fmt == "squid" and ev.bytes >= 50 * 1024 * 1024:
        out.append(f"large proxy transfer ({ev.bytes / 1048576:.0f} MB)")

    if (ev.action == "allow" and ev.direction == "out" and _private(ev.src)
            and _public(ev.dst) and ev.dport not in (80, 443, 53, 123, 22,
                                                     587, 993, 995, 0)):
        out.append(f"allowed outbound to a public host on port {ev.dport}")

    return out


def aggregate(events) -> list[str]:
    """Mutate each event's ``notable`` with cross-event findings; return a
    short list of summary findings."""
    from collections import defaultdict

    blocked_by_src: dict[str, list] = defaultdict(list)
    dports_by_src: dict[str, set] = defaultdict(set)
    dsts_by_src: dict[str, set] = defaultdict(set)
    alerts = 0

    for ev in events:
        if ev.action == "alert":
            alerts += 1
        if ev.action in ("deny", "drop", "reject") and ev.src:
            blocked_by_src[ev.src].append(ev)
        if ev.src and ev.dport:
            dports_by_src[ev.src].add(ev.dport)
            dsts_by_src[ev.src].add(ev.dst)

    findings: list[str] = []
    for src, evs in blocked_by_src.items():
        if len(evs) >= 20:
            note = (f"{src}: {len(evs)} blocked events "
                    f"({len(dports_by_src[src])} ports, "
                    f"{len(dsts_by_src[src])} hosts) - scan / brute force?")
            findings.append(note)
            for ev in evs:
                ev.notable.append("part of a blocked-event burst from "
                                  f"{src}")
    for src, ports in dports_by_src.items():
        if len(ports) >= 50 and len(dsts_by_src[src]) <= 3:
            findings.append(f"{src}: swept {len(ports)} ports on "
                            f"{len(dsts_by_src[src])} host(s) - port scan")
    if alerts:
        findings.append(f"{alerts} IDS alert(s) in the set")
    return findings


_SEV = {
    "IDS alert (severity 1": 3, "IDS alert (severity 2": 3,
    "IDS alert": 2, "credentials embedded": 3,
    "blocked inbound connection": 2, "connection to a commonly-abused": 3,
    "request to a raw-IP host": 2, "large proxy transfer": 2,
    "allowed outbound to a public host on port": 1,
    "part of a blocked-event burst": 2,
}


def severity(notable) -> str:
    top = 0
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k):
                top = max(top, v)
    return {0: "none", 1: "low", 2: "medium", 3: "high"}[top]
