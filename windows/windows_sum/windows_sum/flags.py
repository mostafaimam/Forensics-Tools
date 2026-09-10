"""Heuristic flags for a SUM access aggregate."""

from __future__ import annotations

import ipaddress
import re

_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(a) -> tuple[list[str], str]:
    out: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    ip = None
    try:
        ip = ipaddress.ip_address(a.address)
    except ValueError:
        pass
    if ip is not None:
        if ip.is_global:
            out.append("access from a public IP address")
            bump("medium")
        elif ip.is_loopback:
            out.append("access from loopback")
            bump("low")
    elif a.address and not re.match(r"^[\w.\-]+$", a.address):
        out.append("client address did not decode to an IP")
        bump("low")

    user = (a.user or "").lower()
    if user.endswith("$"):
        out.append("machine / computer account")
        bump("low")
    if re.search(r"\b(administrator|admin|krbtgt|guest)\b", user) or \
            user.endswith(("-500", "-501")):
        out.append("privileged / built-in account")
        bump("low")
    if not a.user and a.total_accesses:
        out.append("access with no authenticated user name")
        bump("low")

    role = (a.role_name or "").lower()
    if "remote desktop" in role or "terminal" in role:
        out.append("Remote Desktop / Terminal Services access")
        bump("low")
    if "active directory" in role:
        out.append("Active Directory access")
        bump("low")

    mx = 0
    for tok in (a.daily or "").split(","):
        tok = tok.strip()
        if ":" in tok:
            try:
                mx = max(mx, int(tok.rsplit(":", 1)[1]))
            except ValueError:
                pass
    if mx >= 100:
        out.append(f"high single-day access count ({mx})")
        bump("medium")

    if ip is not None and ip.is_global and \
            ("remote desktop" in role or "terminal" in role):
        out.append("RDP-role access from a public IP")
        bump("high")

    return out, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
