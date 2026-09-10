"""Heuristic flags for recovered WMI subscription objects."""

from __future__ import annotations

import re

_LOLBIN = re.compile(r"\b(powershell|pwsh|cmd|wscript|cscript|mshta|"
                     r"rundll32|regsvr32|installutil|msbuild|certutil|"
                     r"bitsadmin|curl)\b", re.I)
_ENC = re.compile(r"(-enc\w*\s+[A-Za-z0-9+/=]{16,}|FromBase64String|"
                  r"DownloadString|DownloadFile|IEX|Invoke-Expression|"
                  r"-w\s+hidden|-nop\b|hidden|bypass)", re.I)
_WRITABLE = re.compile(r"[A-Za-z]:\\.*\\(AppData|Temp|ProgramData|"
                       r"Users\\Public|Downloads)\\", re.I)
_PROC_TRIGGER = re.compile(r"__InstanceCreationEvent|__InstanceModification"
                           r"Event|Win32_Process|Win32_ProcessStartTrace|"
                           r"Win32_LogicalDisk|Win32_LocalTime|"
                           r"Win32_VolumeChangeEvent|RegistryTreeChangeEvent|"
                           r"__TimerEvent", re.I)
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(o) -> tuple[list[str], str]:
    n: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    ns = (o.namespace or "").lower()
    if o.otype == "binding":
        n.append("event-subscription binding present")
        bump("medium")
    if o.otype == "consumer":
        n.append(f"event consumer ({o.action_kind})")
        bump("low")
        act = o.action or ""
        if _LOLBIN.search(act):
            n.append("consumer runs a living-off-the-land binary")
            bump("high")
        if _ENC.search(act):
            n.append("consumer payload is encoded / obfuscated / hidden")
            bump("high")
        if _WRITABLE.search(act):
            n.append("consumer executes from a user-writable path")
            bump("high")
        if o.cls == "ActiveScriptEventConsumer":
            n.append("in-memory script consumer (VBScript / JScript)")
            bump("high")
    if o.otype == "filter":
        n.append("event filter")
        bump("low")
        if _PROC_TRIGGER.search(o.query or ""):
            n.append("filter triggers on process / system activity")
            bump("medium")

    if ns and not any(k in ns for k in ("subscription", "default",
                                        "cimv2", "root\\subscription")):
        n.append(f"non-default namespace ({o.namespace})")
        bump("medium")

    if o.otype in ("consumer", "binding") and not o.live:
        n.append("record is on a stale (unmapped) repository page")

    return n, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
