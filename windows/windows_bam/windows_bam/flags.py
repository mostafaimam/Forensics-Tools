"""Heuristic flags for a BAM / DAM execution entry."""

from __future__ import annotations

import re

_WRITABLE = re.compile(r"\\(users\\[^\\]+\\|appdata\\|temp\\|programdata\\|"
                       r"public\\|downloads\\|windows\\temp\\|perflogs\\|"
                       r"\$recycle\.bin\\)", re.I)
_LOLBIN = re.compile(r"\\(powershell|pwsh|mshta|rundll32|regsvr32|wscript|"
                     r"cscript|certutil|bitsadmin|installutil|msbuild|"
                     r"regasm|regsvcs|cmstp|forfiles|wmic|at|schtasks|"
                     r"psexec|winrs)\.exe$", re.I)
_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                 "smss.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
                 "spoolsv.exe", "taskhostw.exe", "dllhost.exe",
                 "runtimebroker.exe", "sihost.exe", "conhost.exe"}
_SYSTEM_DIRS = ("system32\\", "syswow64\\", "\\windows\\", "winsxs\\")


def flag(e) -> list[str]:
    out: list[str] = []
    p = e.path or ""
    low = p.lower()
    base = low.rsplit("\\", 1)[-1]

    if _WRITABLE.search(p):
        out.append(f"executable in a user-writable path ({p})")
    if _LOLBIN.search(p):
        out.append(f"living-off-the-land binary executed ({base})")
    if low.startswith("\\\\") or low.startswith("<vol0>"):
        out.append("executed from a UNC / unusual volume path")
    if base in _SYSTEM_NAMES and not any(d in low for d in _SYSTEM_DIRS):
        out.append(f"system binary name ({base}) outside a system directory")
    if base.endswith((".exe",)) and " " in base:
        out.append("executable name contains a space (possible masquerade)")
    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "executable in a user-writable path": "high",
    "living-off-the-land binary executed": "medium",
    "executed from a UNC / unusual volume path": "medium",
    "system binary name": "high",
    "executable name contains a space": "medium",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
