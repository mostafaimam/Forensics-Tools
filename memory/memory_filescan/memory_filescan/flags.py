"""Heuristic flags for a recovered file name."""

from __future__ import annotations

import re

_EXE = re.compile(r"\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js)$", re.I)
_WRITABLE = re.compile(r"\\(Users\\[^\\]+\\AppData|Temp|ProgramData|"
                       r"Windows\\Temp|Public)\\", re.I)
_ADS = re.compile(r"[^\\:]:[^\\:]")
_SMB = re.compile(r"\\Device\\Mup\\|\\Device\\LanmanRedirector\\", re.I)
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def flag(name: str) -> list[str]:
    out = []
    if _EXE.search(name) and _WRITABLE.search(name):
        out.append("executable / script open from a user-writable path")
    if _ADS.search(name.split("\\")[-1]):
        out.append("alternate data stream")
    if _SMB.search(name):
        out.append("remote (SMB) file object")
    return out


def severity(notable: list[str]) -> str:
    if any("writable" in n for n in notable):
        return "high"
    if notable:
        return "low"
    return "none"


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
