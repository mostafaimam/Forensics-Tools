"""Heuristic flags over a cookie."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_IP_HOST = re.compile(r"^\.?\d{1,3}(\.\d{1,3}){3}$")
_PUNY = re.compile(r"(^|\.)xn--", re.I)
_TUNNEL = ("ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt",
           "serveo.net", "localtunnel.me", "portmap.io", "pagekite.me")
_ANON = ("hide.me", "whoer.net", "proxysite.com", "croxyproxy.com",
         "kproxy.com")
_SUSPECT_TLD = {"zip", "mov", "top", "xyz", "click", "gq", "cf", "tk", "ml",
                "ga", "sbs", "cyou", "rest", "monster"}

# names that indicate an authenticated session
_AUTH_NAME = re.compile(
    r"(^|[_\-.\d])(s?sid|sess(ion)?(id)?|auth|token|jwt|bearer|"
    r"access[_-]?token|refresh[_-]?token|aspxauth|aspnet|phpsessid|"
    r"jsessionid|_session|oauth|id[_-]?token|psid|apsid|hsid|webauth|"
    r"remember[_-]?(me|token))([_\-.\d]|$)", re.I)


def flag(c) -> list[str]:
    out: list[str] = []
    host = (c.host or "").lstrip(".").lower()
    name = c.name or ""

    if _IP_HOST.match(host):
        out.append("ip-literal-host")
    if _PUNY.search(host):
        out.append("punycode-host")
    reg = host.rsplit(".", 1)
    if len(reg) == 2 and reg[1] in _SUSPECT_TLD:
        out.append(f"suspect-tld:.{reg[1]}")
    if any(host == t or host.endswith("." + t) for t in _TUNNEL):
        out.append("tunnel-host")
    if any(host == a or host.endswith("." + a) for a in _ANON):
        out.append("anonymiser-host")

    if _AUTH_NAME.search(name):
        out.append("session/auth-cookie")

    # __Host- / __Secure- prefix rules (RFC 6265bis)
    if name.startswith("__Host-"):
        if not c.secure or c.path != "/" or host.startswith("."):
            out.append("host-prefix-violation")
    if name.startswith("__Secure-") and not c.secure:
        out.append("secure-prefix-violation")

    # implausibly long-lived
    if c.expires:
        try:
            exp = datetime.fromisoformat(c.expires.replace("Z", "+00:00"))
            years = (exp - datetime.now(timezone.utc)).days / 365.25
            if years > 5:
                out.append("expires->5y")
        except ValueError:
            pass

    return out


_SEV = {
    "ip-literal-host": 3, "punycode-host": 3, "tunnel-host": 3,
    "anonymiser-host": 3,
    "session/auth-cookie": 2, "host-prefix-violation": 2,
    "secure-prefix-violation": 2,
    "expires->5y": 1,
}


def severity(notable: list[str]) -> str:
    if not notable:
        return "none"
    top = max((_SEV.get(n.split(":")[0], 1) for n in notable), default=1)
    return {3: "high", 2: "medium", 1: "low"}[top]
