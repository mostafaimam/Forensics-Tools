"""Heuristic flags for a notification."""

from __future__ import annotations

import re

_LOLBIN = re.compile(r"(powershell|pwsh|mshta|rundll32|regsvr32|wscript|"
                     r"cscript|certutil|bitsadmin|wmic|cmd)\.exe", re.I)
_SCRIPT_APP = re.compile(r"\.(ps1|bat|cmd|hta|vbs|js|py)($|\b)", re.I)
_WRITABLE = re.compile(r"[\\/](appdata|temp|programdata|public|downloads)"
                       r"[\\/]", re.I)
_URL = re.compile(r"https?://\S+", re.I)
_IP = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")


def flag(n) -> list[str]:
    out: list[str] = []
    app = n.app or ""

    if _LOLBIN.search(app) or _SCRIPT_APP.search(app):
        out.append(f"notification raised by a script / LOLBin app ({app})")
    if _WRITABLE.search(app):
        out.append(f"notification app id is a user-writable path ({app})")
    if n.ntype == "raw":
        out.append("raw notification (opaque payload - a channel some "
                   "implants use)")
    m = _URL.search(n.text or "")
    if m:
        out.append(f"notification text contains a URL ({m.group(0)[:80]})")
    elif _IP.search(n.text or ""):
        out.append("notification text contains an IP address")
    low = (n.text or "").lower()
    if any(w in low for w in ("password", "verification code", "one-time",
                              "2fa", "otp", "login code")):
        out.append("notification text looks like an authentication code / "
                   "credential prompt")

    seen: set = set()
    return [x for x in out if not (x in seen or seen.add(x))]


_SEV = {
    "notification raised by a script / LOLBin app": "high",
    "notification app id is a user-writable path": "high",
    "raw notification": "medium",
    "notification text contains a URL": "low",
    "notification text contains an IP address": "medium",
    "notification text looks like an authentication code": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for x in notable:
        for k, v in _SEV.items():
            if x.startswith(k) and order[v] > order[top]:
                top = v
    return top
