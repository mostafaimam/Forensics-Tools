"""Heuristic flags for an install record."""

from __future__ import annotations

import re

_SCRIPTY_PROC = re.compile(r"^(sh|bash|zsh|python[0-9.]*|osascript|ruby|perl|"
                           r"curl|node|java|Terminal)$", re.I)
_DL_PKG = re.compile(r"/(Downloads|Desktop|tmp|private/tmp|var/tmp)/[^/]+\."
                     r"(pkg|mpkg|dmg)$", re.I)
_PROFILE = re.compile(r"\.mobileconfig$|configuration profile|ManagedClient",
                      re.I)


def flag(rec, expected_procs) -> list[str]:
    out: list[str] = []
    apple = all(i.startswith(("com.apple.", "com.apple"))
                for i in rec.package_ids) and rec.package_ids

    if rec.process and rec.process not in expected_procs and \
            not rec.process.startswith("com.apple."):
        if _SCRIPTY_PROC.match(rec.process):
            out.append(f"installed by a shell / scripting process "
                       f"({rec.process})")
        else:
            out.append(f"installed by an unexpected process ({rec.process})")

    if rec.pkg_file and _DL_PKG.search("/" + rec.pkg_file.replace("\\", "/")):
        out.append(f"package file came from a download / temp folder "
                   f"({rec.pkg_file})")

    if _PROFILE.search(rec.name) or _PROFILE.search(rec.pkg_file) or \
            rec.content_type == "config-profile":
        out.append("a configuration profile / MDM payload")

    if rec.kind == "receipt" and not rec.correlated and not apple:
        out.append("receipt on disk with no matching InstallHistory entry")
    if rec.kind == "history" and not rec.correlated and not apple and \
            rec.content_type in ("", "software"):
        out.append("install event with no receipt left on disk "
                   "(uninstalled, or a scripted install)")

    if rec.prefix and rec.prefix not in ("/", ""):
        out.append(f"non-standard install prefix ({rec.prefix})")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "installed by a shell / scripting process": "high",
    "installed by an unexpected process": "medium",
    "package file came from a download / temp folder": "medium",
    "a configuration profile / MDM payload": "medium",
    "receipt on disk with no matching InstallHistory entry": "low",
    "install event with no receipt left on disk": "low",
    "non-standard install prefix": "medium",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
