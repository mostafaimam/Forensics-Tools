"""Heuristic flags for a parsed WER report."""

from __future__ import annotations

import re

_WRITABLE = re.compile(r"\\(AppData\\Local\\Temp|AppData\\Local|"
                       r"AppData\\Roaming|\\Temp\\|\\Tmp\\|ProgramData|"
                       r"Users\\Public|Downloads|\$Recycle\.Bin|"
                       r"Windows\\Temp|PerfLogs)\\", re.I)
_LOLBIN = re.compile(r"\\(powershell|pwsh|cmd|wscript|cscript|mshta|"
                     r"rundll32|regsvr32|installutil|msbuild|mavinject|"
                     r"regasm|regsvcs|certutil|bitsadmin|hh|ieexec|"
                     r"presentationhost|msxsl|odbcconf)\.exe$", re.I)
_EXPLOITY_MOD = re.compile(r"\\(ntdll|kernelbase|msvcrt|ucrtbase|vbscript|"
                           r"jscript9?|chakra|flash\w*|mshtml|"
                           r"vcruntime\d*)\.dll$", re.I)
_AV = "0xc0000005"
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(r) -> tuple[list[str], str]:
    n: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    app = r.app_path or r.app_name
    if r.event_type:
        n.append(f"{r.event_type} report (evidence of execution)")
        bump("low")

    if r.app_path and _WRITABLE.search(r.app_path):
        n.append("faulting application ran from a user-writable directory")
        bump("high")
    if r.mod_path and _WRITABLE.search(r.mod_path):
        n.append("faulting module loaded from a user-writable directory")
        bump("high")

    if _LOLBIN.search(r.app_path or "") or (
            r.app_name and _LOLBIN.search("\\" + r.app_name)):
        n.append("faulting application is a living-off-the-land binary")
        bump("medium")

    if r.event_type in ("BEX", "BEX64"):
        n.append("buffer-overflow / DEP violation report (possible exploit)")
        bump("medium")

    code = (r.exception_code or "").lower()
    if code in (_AV, "c0000005"):
        if _EXPLOITY_MOD.search(r.mod_path or "") or \
                (r.mod_name and _EXPLOITY_MOD.search("\\" + r.mod_name)):
            n.append("access violation in a script / runtime module")
            bump("medium")
    if code in ("0xc0000409", "c0000409"):
        n.append("stack buffer overrun (/GS) - exploit or corruption")
        bump("medium")
    if code in ("0xc0000374", "c0000374"):
        n.append("heap corruption")
        bump("low")

    if app and r.app_name and r.app_name.lower() in (
            "regsvr32.exe", "rundll32.exe", "mshta.exe") and \
            r.mod_name and r.mod_path and _WRITABLE.search(r.mod_path):
        n.append("LOLBin crashed loading a module from a writable path")
        bump("high")

    return n, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
