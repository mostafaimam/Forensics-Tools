"""Severity / notable classification for a normalised Defender row."""

from __future__ import annotations

import re

_WRITABLE = re.compile(
    r"\\(AppData|Temp|Tmp|ProgramData|Users\\Public|Windows\\Temp|"
    r"PerfLogs|\$Recycle\.Bin|Downloads)\\", re.I)
_BROAD = re.compile(r"^(?:[A-Za-z]:\\?\*?|\*|[A-Za-z]:\\Users\\?\*?|"
                    r"[A-Za-z]:\\Windows\\?\*?|\\)$")
_LOLBIN = re.compile(
    r"\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|"
    r"certutil|bitsadmin|wmic|installutil|msbuild|forfiles|conhost)\.exe$",
    re.I)

_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(r: dict) -> tuple[list[str], str]:
    notable: list[str] = []
    sev = "none"
    kind = r.get("kind", "")
    path = r.get("path", "") or ""
    detail = (r.get("detail", "") or "")
    low = detail.lower()

    def bump(to):
        nonlocal sev
        if _ORDER[to] > _ORDER[sev]:
            sev = to

    if kind == "quarantine" or kind.endswith("detection"):
        notable.append("threat detected / quarantined")
        bump("high")
    if kind == "action" or kind.endswith("-action"):
        if "failed" in low or "could not" in low:
            notable.append("remediation failed")
            bump("high")

    if kind.startswith("exclusion") or kind == "mplog-exclusion":
        cat = kind.split("-")[-1]
        notable.append(f"defender exclusion configured ({cat})")
        bump("low")
        if _BROAD.match(path.strip()) or path.strip() in ("*", ""):
            notable.append("exclusion covers an entire drive / tree")
            bump("high")
        elif _WRITABLE.search(path):
            notable.append("exclusion of a user-writable path")
            bump("medium")
        elif _LOLBIN.search(path):
            notable.append("exclusion of a living-off-the-land binary")
            bump("high")

    if r.get("kind") == "protection-setting":
        notable.append("protection setting changed")
        pv = path.lower()
        if "= 1" in pv or "disabled" in low:
            notable.append(detail.split(" (")[0])
            bump("high")
        else:
            bump("medium")

    if "evtx-tamper" in kind:
        notable.append("real-time protection / configuration tampering")
        bump("high")
    if "evtx-signature" in kind and ("failed" in low):
        notable.append("signature / engine update failed")
        bump("low")

    if _LOLBIN.search(path) and sev != "none":
        notable.append("living-off-the-land binary involved")

    return notable, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
