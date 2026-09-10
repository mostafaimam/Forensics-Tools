"""Heuristic flags for a reconstructed shellbag folder."""

from __future__ import annotations

import re

_WRITABLE = re.compile(r"\\(users\\[^\\]+\\appdata|appdata|temp|tmp|"
                       r"programdata|\$recycle\.bin|perflogs|public\\)",
                       re.I)
_OTHER_PROFILE = re.compile(r"\\users\\([^\\]+)(?:\\|$)", re.I)
_ARCHIVE = re.compile(r"\.(zip|7z|rar|tar|gz|cab|iso)(\\|$)", re.I)
_IMAGE_MOUNT = re.compile(r"\.(vhdx?|e01|raw|dd|img)(\\|$)", re.I)
_OFFENSIVE = re.compile(
    r"\\(downloads|desktop|temp|public)\\.*\b("
    r"tools|toolkit|mimikatz|psexec|winpeas|linpeas|seatbelt|rubeus|"
    r"sharphound|bloodhound|cobalt|metasploit|nishang|powersploit|"
    r"impacket|nmap|netcat|\bnc\b|chisel|ligolo)\b", re.I)


def flag(b, *, account_user: str = "") -> list[str]:
    out: list[str] = []
    p = b.path or ""
    low = p.lower()
    t = b.item_type

    if t == "network" or low.startswith("\\\\"):
        out.append(f"network / UNC path browsed ({p})")
    if t == "drive" and b.name[:1].isalpha() and b.name[:2].endswith(":") \
            and b.name[0].upper() not in ("C",):
        out.append(f"non-system drive browsed ({b.name})")
    if _ARCHIVE.search(p):
        out.append("browsed inside an archive / image file")
    elif _IMAGE_MOUNT.search(low) and t in ("directory", "drive"):
        out.append("disk-image / VHD path in the shellbag tree")
    if _WRITABLE.search(p):
        out.append("folder under a user-writable / staging path")
    m = _OTHER_PROFILE.search(p)
    if m and account_user and m.group(1).lower() != account_user.lower() \
            and m.group(1).lower() not in ("public", "default", "all users"):
        out.append(f"another user's profile browsed ({m.group(1)})")
    if t == "known-folder" and b.guid and b.name.startswith("{"):
        out.append("GUID-only known-folder entry (does not resolve to a name)")
    if _OFFENSIVE.search(p):
        out.append("folder name suggests offensive tooling")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "network / UNC path browsed": "medium",
    "non-system drive browsed": "low",
    "browsed inside an archive / image file": "medium",
    "disk-image / VHD path in the shellbag tree": "medium",
    "folder under a user-writable / staging path": "low",
    "another user's profile browsed": "high",
    "GUID-only known-folder entry": "low",
    "folder name suggests offensive tooling": "high",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
