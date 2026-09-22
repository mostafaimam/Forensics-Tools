"""Permissive key/value parsing for OneDrive's *.ini-shaped settings files.

The exact key names OneDrive uses are undocumented and have varied
across client versions, so every ``key = value`` (or ``key:value``)
line is captured as-is rather than assuming specific keys exist.
"""

from __future__ import annotations

import re

_LINE = re.compile(r"^\s*([^=:\s][^=:]*?)\s*[:=]\s*(.*?)\s*$")


def parse_settings_file(path) -> dict[str, str]:
    out = {}
    try:
        text = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return out
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith((";", "#", "[")):
            continue
        m = _LINE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out
