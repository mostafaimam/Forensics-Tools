"""Heuristic flags for a TCC grant."""

from __future__ import annotations

import re

# permissions an attacker wants
_HIGH_IMPACT = {
    "kTCCServiceAccessibility", "kTCCServiceScreenCapture",
    "kTCCServiceListenEvent", "kTCCServicePostEvent",
    "kTCCServiceSystemPolicyAllFiles", "kTCCServiceAppleEvents",
    "kTCCServiceDeveloperTool", "kTCCServiceAll",
}

_CLI_CLIENT = re.compile(
    r"(^|/|\.)(terminal|iterm2?|osascript|python[0-9.]*|ruby|perl|node|"
    r"bash|zsh|sh|curl|wget|swift|java|electron|automator)($|\b)", re.I)
_WRITABLE_PATH = re.compile(
    r"^/(tmp|private/tmp|var/tmp|var/folders|Users/[^/]+|Users/Shared)/",
    re.I)
_UNSIGNED_HINT = re.compile(r"^/(Users|tmp|opt|usr/local)/", re.I)


def flag(g) -> list[str]:
    out: list[str] = []
    granted = g.decision in ("allowed", "limited")
    client = g.client or ""
    base = client.rsplit("/", 1)[-1] if "/" in client else \
        client.rsplit(".", 1)[-1]

    if granted and g.service_raw in _HIGH_IMPACT:
        if _CLI_CLIENT.search(base) or _CLI_CLIENT.search(client):
            out.append(f"high-impact permission ({g.service}) granted to a "
                       f"command-line / scripting tool ({base})")
        elif g.client_type == "path" and _WRITABLE_PATH.match(client):
            out.append(f"high-impact permission ({g.service}) granted to a "
                       f"binary in a user-writable path")
        elif g.client_type == "path" and not client.lower().startswith(
                ("/applications/", "/system/")):
            out.append(f"high-impact permission granted ({g.service}) to a "
                       f"binary outside /Applications")

    if granted and g.service_raw == "kTCCServiceListenEvent":
        out.append("input-monitoring / keystroke-capture permission granted")

    if granted and g.service_raw == "kTCCServiceAppleEvents" and \
            g.indirect_object in ("com.apple.systemevents",
                                  "com.apple.systemuiserver",
                                  "com.apple.finder"):
        out.append(f"Automation control over {g.indirect_object} "
                   f"(scriptable system control)")

    if g.client_type == "path" and _UNSIGNED_HINT.match(client) and granted:
        out.append("client is an absolute path outside /Applications "
                   "(likely unsigned / ad-hoc)")

    if g.from_profile and g.service_raw in _HIGH_IMPACT:
        out.append("high-impact permission pushed by a configuration profile "
                   "/ MDM")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "high-impact permission (": "high",
    "high-impact permission granted (": "medium",
    "input-monitoring / keystroke-capture permission granted": "high",
    "Automation control over": "high",
    "client is an absolute path outside /Applications": "medium",
    "high-impact permission pushed by a configuration profile": "medium",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
