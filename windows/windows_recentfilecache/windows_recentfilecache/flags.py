"""Heuristic flags for a RecentFileCache path."""

from __future__ import annotations

import re

_WRITABLE = re.compile(r"\\(AppData\\Local\\Temp|AppData\\Local|"
                       r"AppData\\Roaming|\\Temp\\|\\Tmp\\|ProgramData|"
                       r"Users\\Public|Downloads|\$Recycle\.Bin|"
                       r"Windows\\Temp|PerfLogs)\\", re.I)
_LOLBIN = re.compile(r"\\(powershell|pwsh|cmd|wscript|cscript|mshta|"
                     r"rundll32|regsvr32|installutil|msbuild|certutil|"
                     r"bitsadmin|at|schtasks|sc|net|net1|reg|wmic|"
                     r"cmstp|regsvcs|regasm|odbcconf|mavinject)\.exe$", re.I)
_SUS_EXT = re.compile(r"\.(scr|pif|com|cpl|hta|jar|vbs|vbe|js|jse|wsf|wsh|"
                      r"ps1|bat|cmd)$", re.I)
_DOUBLE_EXT = re.compile(r"\.(doc|docx|pdf|xls|xlsx|jpg|png|txt|rtf|zip)"
                         r"\s*\.(exe|scr|com|pif|bat|cmd|js|vbs)$", re.I)
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(path: str) -> tuple[list[str], str]:
    n: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    low = path.lower()
    if _WRITABLE.search(path):
        n.append("executable in a user-writable directory")
        bump("high")
    if _DOUBLE_EXT.search(low):
        n.append("double extension (masquerading)")
        bump("high")
    if _SUS_EXT.search(low):
        n.append("script / non-PE executable type")
        bump("medium")
    if _LOLBIN.search(low):
        n.append("living-off-the-land binary")
        bump("low")
    if low.startswith("\\\\") or re.match(r"^[a-z]:\\\$recycle", low):
        n.append("path is a UNC share or the recycle bin")
        bump("medium")
    if re.search(r"\\[0-9a-f]{8,}\.exe$", low) or \
            re.search(r"\\[a-z]{1,3}\.exe$", low):
        n.append("randomised / very short executable name")
        bump("low")
    return n, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
