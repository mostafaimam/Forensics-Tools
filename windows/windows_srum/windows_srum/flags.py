"""Heuristic flags for a normalised SRUM row."""

from __future__ import annotations

import re

_WRITABLE = re.compile(
    r"\\(users\\[^\\]+\\appdata|appdata|temp|tmp|programdata|public|"
    r"downloads|\$recycle\.bin|perflogs|windows\\temp)\\", re.I)
_LOLBIN = re.compile(
    r"\\(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|"
    r"bitsadmin|msbuild|installutil|wmic|curl|ftp|net|nltest|"
    r"cmd)\.exe$", re.I)
_BIG_EGRESS = 50 * 1024 * 1024        # 50 MiB sent in one hourly bucket


def flag(r) -> list[str]:
    out: list[str] = []
    app = r.app or ""

    if _WRITABLE.search(app):
        out.append(f"app ran from a user-writable path ({app})")
    if _LOLBIN.search(app):
        out.append(f"living-off-the-land binary recorded ({app.split(chr(92))[-1]})")

    if r.provider == "network-data":
        sent = r.fields.get("bytes_sent") or 0
        recvd = r.fields.get("bytes_recvd") or 0
        try:
            sent = int(sent)
            recvd = int(recvd)
        except (TypeError, ValueError):
            sent = recvd = 0
        if sent >= _BIG_EGRESS:
            out.append(f"large outbound transfer in one hour "
                       f"({sent / 1048576:.1f} MiB sent)")
        if sent > 0 and recvd == 0 and sent > 1024 * 1024:
            out.append("upload-only traffic (bytes sent, nothing received)")
        if (_WRITABLE.search(app) or _LOLBIN.search(app)) and sent > 0:
            out.append("network usage by a writable-path / LOLBin process")

    if r.provider == "push-notification" and _LOLBIN.search(app):
        out.append("push-notification activity by a LOLBin")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "app ran from a user-writable path": "medium",
    "living-off-the-land binary recorded": "medium",
    "large outbound transfer in one hour": "high",
    "upload-only traffic": "medium",
    "network usage by a writable-path / LOLBin process": "high",
    "push-notification activity by a LOLBin": "medium",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
