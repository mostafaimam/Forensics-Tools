"""Heuristic flags for an aggregated flow conversation."""

from __future__ import annotations

import ipaddress
import statistics

_MB = 1024 * 1024


def _reserved(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return (a.is_multicast or a.is_reserved or a.is_unspecified
                or a.is_link_local)
    except ValueError:
        return False


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def flag(c, peers: set) -> list[str]:
    out: list[str] = []
    tb = c.total_bytes

    if tb >= 100 * _MB:
        out.append(f"large transfer ({tb / _MB:.0f} MB)")
    elif tb >= 10 * _MB:
        out.append(f"sizeable transfer ({tb / _MB:.0f} MB)")

    if c.duration >= 3600:
        out.append(f"long-lived flow ({c.duration / 3600:.1f} h)")

    # egress-heavy: far more sent from the client than received
    if c.c2s_bytes >= 5 * _MB and c.c2s_bytes >= 10 * max(c.s2c_bytes, 1) \
            and _public(c.server):
        out.append(f"outbound-heavy ({c.c2s_bytes / _MB:.0f} MB up / "
                   f"{c.s2c_bytes / _MB:.1f} MB down) - exfil?")

    # horizontal scan: one client, many distinct servers
    if len(peers) >= 25:
        out.append(f"client contacted {len(peers)} hosts (scan / sweep?)")

    # port probe: TCP with only SYN seen, tiny volume
    if c.proto == 6 and (c.tcp_flags & 0x02) and not (c.tcp_flags & 0x10) \
            and c.total_packets <= 3:
        out.append("SYN with no ACK (port probe / filtered)")

    # beaconing: several similar-sized flows at a regular cadence
    ts = sorted(t for t, _b in c.sizes if t)
    if len(ts) >= 4:
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
        szs = [b for _t, b in c.sizes if b]
        if gaps and statistics.mean(gaps) > 0:
            jitter = statistics.pstdev(gaps) / statistics.mean(gaps)
            size_cv = (statistics.pstdev(szs) / statistics.mean(szs)
                       if len(szs) >= 2 and statistics.mean(szs) else 1.0)
            if jitter < 0.25 and size_cv < 0.25 and \
                    20 <= statistics.mean(gaps) <= 86400:
                out.append(
                    f"regular beacon (~{statistics.mean(gaps):.0f}s interval, "
                    f"{len(ts)} flows)")

    if _reserved(c.server) or _reserved(c.client):
        out.append("reserved / bogon address")

    return out


_SEV = {
    "large transfer": 2, "outbound-heavy": 3, "regular beacon": 3,
    "client contacted": 3, "SYN with no ACK": 2, "long-lived flow": 1,
    "sizeable transfer": 1, "reserved / bogon": 2,
}


def severity(notable) -> str:
    top = 0
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k):
                top = max(top, v)
    return {0: "none", 1: "low", 2: "medium", 3: "high"}[top]
