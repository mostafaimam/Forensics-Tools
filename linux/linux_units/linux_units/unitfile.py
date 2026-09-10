"""Parse a systemd unit file (INI-ish, with repeated keys)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_SECTION = re.compile(r"^\[(.+?)\]\s*$")
# a line continuation ends with a backslash
_CONT = re.compile(r"\\\s*$")


@dataclass
class UnitData:
    sections: dict = field(default_factory=dict)   # name -> list[(key, value)]

    def get_all(self, section: str, key: str) -> list[str]:
        out = []
        for k, v in self.sections.get(section, []):
            if k.lower() == key.lower():
                out.append(v)
        return out

    def get(self, section: str, key: str, default: str = "") -> str:
        vals = self.get_all(section, key)
        return vals[-1] if vals else default


def parse_text(text: str) -> UnitData:
    ud = UnitData()
    section = None
    buf: list[str] = []
    pending_key = None
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        if pending_key is not None:
            buf.append(stripped.rstrip("\\").strip())
            if not _CONT.search(line):
                ud.sections.setdefault(section, []).append(
                    (pending_key, " ".join(buf).strip()))
                pending_key, buf = None, []
            continue
        if not stripped or stripped[0] in "#;":
            continue
        m = _SECTION.match(stripped)
        if m:
            section = m.group(1)
            ud.sections.setdefault(section, [])
            continue
        if "=" not in stripped or section is None:
            continue
        key, _, val = stripped.partition("=")
        key = key.strip()
        val = val.strip()
        if _CONT.search(line):
            pending_key = key
            buf = [val.rstrip("\\").strip()]
        else:
            ud.sections.setdefault(section, []).append((key, val))
    if pending_key is not None:
        ud.sections.setdefault(section, []).append(
            (pending_key, " ".join(buf).strip()))
    return ud


def merge(base: UnitData, override: UnitData) -> UnitData:
    """Apply a drop-in on top of *base*.

    An empty assignment (``ExecStart=``) resets a list-valued key.
    """
    out = UnitData({s: list(v) for s, v in base.sections.items()})
    for section, pairs in override.sections.items():
        cur = out.sections.setdefault(section, [])
        for key, val in pairs:
            if val == "":
                out.sections[section] = [(k, v) for k, v in cur
                                         if k.lower() != key.lower()]
                cur = out.sections[section]
            else:
                # scalar keys replace; Exec*/After/etc append
                if key.lower() in _APPEND_KEYS:
                    cur.append((key, val))
                else:
                    out.sections[section] = [(k, v) for k, v in cur
                                             if k.lower() != key.lower()]
                    cur = out.sections[section]
                    cur.append((key, val))
    return out


_APPEND_KEYS = {
    "execstartpre", "execstartpost", "execstoppost", "execreload",
    "environmentfile", "after", "before", "requires", "wants", "wantedby",
    "requiredby", "conflicts", "documentation",
}
