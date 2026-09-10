"""Heuristic flags for a PowerLog event."""

from __future__ import annotations

import re
from datetime import datetime

_MEDIA_APPS = re.compile(
    r"(facetime|photo|camera|zoom|teams|webex|skype|slack|discord|"
    r"obs|quicktime|hangouts|meet|whatsapp|signal|telegram|messages|"
    r"cameracapture|avconference|VDCAssistant|appleh13camera)", re.I)
_SCRIPTY = re.compile(
    r"^(sh|bash|zsh|dash|python[0-9.]*|osascript|ruby|perl|node|nc|ncat|"
    r"socat|curl|wget|Terminal|iTerm2?)$", re.I)
_PATH_BUNDLE = re.compile(r"^/(tmp|private/tmp|var/tmp|Users/)")


def flag(e) -> list[str]:
    out: list[str] = []
    v = e.value or ""

    if e.kind in ("camera", "microphone"):
        state = (e.detail or "").lower()
        active = state in ("1", "true", "active", "on", "start", "started") \
            or "start" in state or "active" in state or state == ""
        if active and v and not _MEDIA_APPS.search(v):
            out.append(f"{e.kind} used by a non-media client ({v})")

    if e.kind == "process" and v:
        base = v.rsplit("/", 1)[-1]
        if _SCRIPTY.match(base):
            out.append(f"shell / interpreter / net tool started ({base})")
        if _PATH_BUNDLE.match(v):
            out.append(f"process runs from a user-writable path ({v})")

    if e.kind == "app usage" and _PATH_BUNDLE.match(v):
        out.append(f"app bundle id is an absolute path ({v})")

    if e.kind == "location" and e.latitude and e.timestamp:
        try:
            dt = datetime.strptime(e.timestamp[:19], "%Y-%m-%dT%H:%M:%S")
            if dt.hour < 6 or dt.hour >= 23:
                out.append(f"location fix recorded overnight "
                           f"({e.latitude},{e.longitude})")
        except ValueError:
            pass

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "camera used by a non-media client": "high",
    "microphone used by a non-media client": "high",
    "shell / interpreter / net tool started": "medium",
    "process runs from a user-writable path": "high",
    "app bundle id is an absolute path": "high",
    "location fix recorded overnight": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
