"""Heuristic flags for a recovered file handle."""

from __future__ import annotations

import re

_EXE = re.compile(r"\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js)$", re.I)
_WRITABLE = re.compile(r"\\(Users\\[^\\]+\\AppData|Temp|ProgramData|"
                       r"Windows\\Temp|Public)\\", re.I)
_SENSITIVE = re.compile(r"\\(lsass\.dmp|SAM|SYSTEM|SECURITY|NTUSER\.DAT|"
                        r"ntds\.dit)$", re.I)
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def flag(process: str, name: str) -> list[str]:
    out = []
    if _EXE.search(name) and _WRITABLE.search(name):
        out.append("executable / script handle to a user-writable path")
    if _SENSITIVE.search(name):
        out.append("handle to a sensitive credential / hive file")
    if "lsass" not in process.lower() and re.search(r"lsass\.dmp$", name,
                                                     re.I):
        out.append(f"non-lsass process ({process}) holding a handle to "
                   f"an LSASS dump")
    return out


def severity(notable: list[str]) -> str:
    if any("sensitive" in n or "lsass" in n for n in notable):
        return "high"
    if notable:
        return "medium"
    return "none"


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
