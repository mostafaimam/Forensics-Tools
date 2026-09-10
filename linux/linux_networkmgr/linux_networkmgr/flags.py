"""Heuristic flags for a network-config item."""

from __future__ import annotations

import re

_PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "76.76.2.0", "94.140.14.14",
    "2001:4860:4860::8888", "2606:4700:4700::1111",
}
_OPEN_SEC = {"", "none", "open"}
_SEC_DOMAIN = re.compile(
    r"(windowsupdate|update\.microsoft|download\.microsoft|clamav|"
    r"virustotal|malwarebytes|sophos|kaspersky|symantec|mcafee|"
    r"crowdstrike|defender|deb\.debian|security\.ubuntu|"
    r"pypi\.org|files\.pythonhosted)", re.I)


def _is_private(ip: str) -> bool:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)", ip)
    if not m:
        return ip.startswith(("fd", "fe80", "::1"))
    a, b = int(m.group(1)), int(m.group(2))
    return (a == 10 or a == 127 or (a == 192 and b == 168)
            or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254))


def flag(it) -> list[str]:
    out: list[str] = []

    if it.secret_stored == "psk":
        out.append("Wi-Fi PSK stored in the clear (not agent-owned)")
    elif it.secret_stored == "wep":
        out.append("WEP key stored (obsolete, trivially broken)")
    elif it.secret_stored == "802-1x":
        out.append("802.1x password / private-key secret stored in the file")
    elif it.secret_stored == "vpn":
        out.append("VPN credential stored in the connection file")

    if it.conn_type == "wifi" and it.security.lower() in _OPEN_SEC \
            and not it.secret_stored \
            and str(it.autoconnect).lower() in ("", "true", "yes", "1") \
            and it.kind in ("nm-connection", "wpa-network"):
        out.append("autoconnect to an open (unencrypted) Wi-Fi network")

    if it.cloned_mac and it.cloned_mac.lower() not in (
            "permanent", "preserve", "random", "stable"):
        out.append(f"cloned / spoofed MAC address ({it.cloned_mac})")

    if it.proxy:
        out.append(f"proxy configured ({it.proxy})")

    for ns in re.split(r"[;, ]+", it.dns or ""):
        ns = ns.strip()
        if not ns:
            continue
        if ns in _PUBLIC_DNS:
            out.append(f"public DNS server set ({ns})")
        elif it.kind == "resolv" and not _is_private(ns) and \
                ns not in _PUBLIC_DNS:
            out.append(f"external DNS server ({ns})")

    if it.kind == "hosts-entry":
        low = (it.detail or "").lower()
        if _SEC_DOMAIN.search(low):
            out.append("/etc/hosts overrides a security / update domain")
        elif it.addresses in ("0.0.0.0", "127.0.0.1", "::1") and \
                re.search(r"\.(com|net|org|io)\b", low):
            out.append("/etc/hosts blackholes a public domain")
        elif not _is_private(it.addresses) and re.search(
                r"\.(com|net|org|io|dev|gov)\b", low):
            out.append(f"/etc/hosts maps a public domain to {it.addresses}")
        else:
            out.append("non-standard /etc/hosts entry")

    if it.vpn_gateway and not _is_private(it.vpn_gateway.split(":")[0]):
        out.append(f"VPN to an external gateway ({it.vpn_gateway})")

    return out


_SEV = {
    "Wi-Fi PSK stored in the clear": "low",
    "WEP key stored": "medium",
    "802.1x password / private-key secret stored": "medium",
    "VPN credential stored": "medium",
    "autoconnect to an open (unencrypted) Wi-Fi": "medium",
    "cloned / spoofed MAC address": "medium",
    "proxy configured": "medium",
    "public DNS server set": "low",
    "external DNS server": "medium",
    "/etc/hosts overrides a security / update domain": "high",
    "/etc/hosts blackholes a public domain": "high",
    "/etc/hosts maps a public domain": "medium",
    "non-standard /etc/hosts entry": "low",
    "VPN to an external gateway": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
