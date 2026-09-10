"""Heuristic flags for a carved BITS file record."""

from __future__ import annotations

import re

_IP_HOST = re.compile(r"^(?:https?|ftp)://(?:\[[0-9a-f:]+\]|(?:\d{1,3}\.){3}"
                      r"\d{1,3})(?::\d+)?(?:/|$)", re.I)
_EXE = re.compile(r"\.(exe|dll|scr|ps1|psm1|bat|cmd|vbs|js|jse|wsf|hta|"
                  r"lnk|sys|cpl|msi|jar|py)$", re.I)
_SYSDIR = re.compile(r"\\Windows\\(System32|SysWOW64|Tasks|Temp)\\", re.I)
_WRITABLE = re.compile(r"\\(AppData|Temp|ProgramData|Users\\Public|"
                       r"Downloads|\$Recycle)", re.I)
_SUS_TLD = re.compile(r"://[^/]+\.(top|xyz|tk|ml|ga|cf|gq|ru|su|zip|mov|"
                      r"click|country|download|work)(?:[:/]|$)", re.I)
_SVC_SID = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(f) -> tuple[list[str], str]:
    n: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    url = f.url or ""
    dest = f.dest or ""
    tmp = f.tmp_file or ""

    if _IP_HOST.match(url):
        n.append("transfer to / from a raw IP address")
        bump("high")
    if _SUS_TLD.search(url):
        n.append("suspicious top-level domain in URL")
        bump("medium")
    if url[:7].lower() == "http://":
        n.append("cleartext HTTP transfer")
        bump("low")

    if _EXE.search(dest) or _EXE.search(url) or _EXE.search(tmp):
        n.append("executable / script payload")
        bump("medium")
    if _SYSDIR.search(dest):
        n.append("destination in a Windows system directory")
        bump("high")
    elif _WRITABLE.search(dest):
        n.append("destination in a user-writable directory")
        bump("low")

    if f.job_type == "upload" or f.job_type == "upload-reply":
        n.append("upload job (possible exfiltration)")
        bump("medium")

    if f.owner and f.owner not in _SVC_SID and \
            not f.owner.endswith(("-500", "-501")):
        n.append("job owned by a user account")
    elif f.owner in _SVC_SID and (_IP_HOST.match(url) or _EXE.search(dest)):
        n.append("service-owned job fetching a payload")
        bump("high")

    name = (f.job_name or "").lower()
    if name and any(w in name for w in ("update", "microsoft", "windows",
                                        "adobe", "google")) and \
            (_IP_HOST.match(url) or _SUS_TLD.search(url)):
        n.append("job name mimics a legitimate updater")
        bump("high")

    if _EXE.search(dest) and _IP_HOST.match(url):
        bump("high")

    return n, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
