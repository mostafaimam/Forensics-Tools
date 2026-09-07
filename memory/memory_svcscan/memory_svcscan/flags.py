"""Heuristic flags over a recovered service record."""

from __future__ import annotations

import re

_USER_WRITABLE = re.compile(
    r"\\(users|appdata|temp|tmp|programdata|downloads|public|perflogs|"
    r"\$recycle\.bin|windows\\temp)\\", re.I)
_LOLBIN = re.compile(
    r"\b(rundll32|regsvr32|powershell|pwsh|cmd|mshta|wscript|cscript|"
    r"installutil|msbuild|certutil|bitsadmin)\b", re.I)
_RANDOMISH = re.compile(r"^[a-f0-9]{8,}$|^[A-Za-z0-9]{16,}$")
_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                   r"[0-9a-f]{12}\}?", re.I)


def flag(name: str, binary_path: str, svc_type: str, state: str) -> list[str]:
    out: list[str] = []
    bp = binary_path or ""
    low = bp.lower()

    if _USER_WRITABLE.search(bp):
        out.append("user-writable-path")
    if _LOLBIN.search(bp):
        out.append("lolbin-service-binary")
    if bp and "\\" not in bp and "/" not in bp and not bp.startswith("%"):
        out.append("no-directory")
    if "driver" in svc_type and _USER_WRITABLE.search(bp):
        out.append("driver-from-user-path")
    # unquoted path with a space before the first argument (privesc)
    if bp and not bp.startswith('"') and " " in bp.split(".exe")[0] \
            and ".exe" in low:
        out.append("unquoted-path")
    # svchost hosting a DLL outside the system directories
    if "svchost" in low and "servicedll" not in low:
        pass
    if _RANDOMISH.match(name) or _GUID.search(name):
        out.append("random-name")
    if not bp:
        out.append("no-binary-path")
    return out


_SEV = {
    "driver-from-user-path": 3, "user-writable-path": 3,
    "lolbin-service-binary": 3, "unquoted-path": 2, "no-directory": 2,
    "random-name": 2, "no-binary-path": 1,
}


def severity(notable: list[str]) -> str:
    if not notable:
        return "none"
    return {3: "high", 2: "medium", 1: "low"}[
        max(_SEV.get(n, 1) for n in notable)]
