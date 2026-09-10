"""Flag dangerous shims / patches in an SDB record."""

from __future__ import annotations

import re

# shims that give code execution, injection or redirection
_DANGEROUS = {
    "injectdll": ("DLL injection into the target process", "high"),
    "loadlibraryredirect": ("redirects LoadLibrary calls", "high"),
    "redirectexe": ("replaces the executable that is launched", "high"),
    "redirectshortcut": ("redirects a shortcut target", "high"),
    "correctfilepaths": ("redirects file-system paths", "medium"),
    "virtualregistry": ("redirects / virtualises registry access", "medium"),
    "disablenxshowui": ("disables DEP for the target", "medium"),
    "runasadmin": ("forces the target to run elevated", "medium"),
    "forceadminaccess": ("fakes administrator access checks", "medium"),
    "elevatecreateprocess": ("elevates child processes", "medium"),
    "emulateheap": ("substitutes a custom heap implementation", "medium"),
    "ignoreexception": ("swallows exceptions in the target", "low"),
    "shimviamemory": ("applies the shim from memory", "high"),
    "hooksleep": ("hooks Sleep", "low"),
}
_SYSDLL = re.compile(r"^(apphelp|acgenral|aclayers|acspecfc|acwin\w*|"
                     r"acxtrnal|kernelbase)\.dll$", re.I)
_WRITABLE = re.compile(r"\\(AppData|Temp|ProgramData|Users\\Public|"
                       r"Downloads)\\", re.I)
_SYS_TARGET = re.compile(r"^(svchost|explorer|lsass|winlogon|services|"
                         r"csrss|smss|wininit|spoolsv|taskhost\w*|dllhost|"
                         r"rundll32|regsvr32|powershell|cmd)\.exe$", re.I)
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(rec, *, is_system_db: bool) -> tuple[list[str], str]:
    n: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    names = []
    if rec.kind == "shim":
        names = [rec.name]
    elif rec.kind in ("exe", "layer"):
        names = list(rec.shims)

    for s in names:
        key = re.sub(r"[^a-z]", "", (s or "").lower())
        for k, (desc, lvl) in _DANGEROUS.items():
            if k in key:
                n.append(f"{s or k}: {desc}")
                bump(lvl)

    if rec.kind == "patch" or (rec.kind == "exe" and rec.patches):
        n.append("custom binary patch (in-place code modification)")
        bump("high")

    if rec.kind == "shim" and rec.dll and not _SYSDLL.match(rec.dll):
        n.append(f"shim DLL is not a standard AppCompat module ({rec.dll})")
        bump("high")
        if _WRITABLE.search(rec.dll):
            n.append("shim DLL path is user-writable")

    if rec.kind == "exe":
        for m in rec.matches:
            base = m.split(" (")[0]
            if _SYS_TARGET.match(base) and (rec.shims or rec.patches):
                n.append(f"shim targets a Windows system binary ({base})")
                bump("high")

    if not is_system_db and rec.kind == "database":
        n.append("custom shim database (not the system sysmain.sdb)")
        bump("medium")

    return n, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
