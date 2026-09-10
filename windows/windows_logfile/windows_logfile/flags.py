"""Heuristic flags for a reconstructed $LogFile event."""

from __future__ import annotations

import re

_EXE = re.compile(r"\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js|jse|hta|lnk|"
                  r"cpl|ocx)$", re.I)
_ADS = re.compile(r":[^:\\/]+$")            # name:stream
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(ev, *, twin_delete=False, twin_create=False) -> tuple[list[str],
                                                                   str]:
    n: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    name = ev.name or ""
    low = name.lower()

    if "deleted" in ev.action:
        n.append("file deletion")
        bump("low")
        if _EXE.search(low):
            n.append("deletion of an executable / script")
            bump("medium")
    if "created" in ev.action:
        n.append("file creation")
        bump("low")
        if _EXE.search(low):
            n.append("creation of an executable / script")
            bump("low")

    if _ADS.search(name) and not re.match(r"^[a-z]:$", low):
        n.append("alternate data stream in the name")
        bump("medium")

    if ev.namespace == "DOS" and "created" in ev.action:
        n.append("DOS (8.3) short-name entry")

    if twin_create and twin_delete:
        n.append("file created and deleted within the log window "
                 "(anti-forensics / staging)")
        bump("high")

    if "timestamps updated" in ev.action and ev.created and ev.modified \
            and ev.created > ev.modified:
        n.append("creation time later than modification time (timestomp)")
        bump("high")

    if ev.name and re.search(r"\\?(temp|tmp|\$recycle\.bin|appdata\\local\\"
                             r"temp)\\", low):
        n.append("path component under a temp / recycle directory")
        bump("low")

    return n, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
