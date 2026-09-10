"""Heuristic flags for a per-process network-usage record."""

from __future__ import annotations

import re

_LOLBIN = re.compile(r"^(sh|bash|zsh|dash|python[0-9.]*|osascript|ruby|perl|"
                     r"node|nc|ncat|netcat|socat|curl|wget|nscurl|ftp|"
                     r"scp|ssh|rsync|Terminal|iTerm2?)$", re.I)
_PATH = re.compile(r"^/(tmp|private/tmp|var/tmp|Users/)")
_BIG_EGRESS = 100 * 1024 * 1024        # 100 MiB


def flag(p) -> list[str]:
    out: list[str] = []
    base = (p.process or "").rsplit("/", 1)[-1]
    scripty = bool(_LOLBIN.match(base))
    pathlike = bool(_PATH.match(p.process or ""))
    has_net = (p.total_in + p.total_out) > 0

    if p.total_out >= _BIG_EGRESS:
        out.append(f"large outbound transfer ({p.total_out / 1048576:.1f} "
                   f"MiB sent)")
    if p.total_out > 5 * 1024 * 1024 and p.total_in * 20 < p.total_out:
        out.append("upload-heavy traffic (far more sent than received)")

    if scripty and has_net:
        out.append(f"network usage by a shell / scripting / transfer tool "
                   f"({base})")
    if pathlike and has_net:
        out.append(f"network usage by a process in a user-writable path "
                   f"({p.process})")
    if (p.wwan_in + p.wwan_out) > 1024 * 1024 and (scripty or pathlike):
        out.append("cellular (WWAN) usage by a script / writable-path "
                   "process")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "large outbound transfer": "high",
    "upload-heavy traffic": "medium",
    "network usage by a shell / scripting / transfer tool": "high",
    "network usage by a process in a user-writable path": "high",
    "cellular (WWAN) usage by a script / writable-path process": "high",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
