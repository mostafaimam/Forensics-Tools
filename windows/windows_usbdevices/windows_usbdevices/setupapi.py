"""Extract per-device first-seen timestamps from setupapi.dev.log."""

from __future__ import annotations

import re
from datetime import datetime

_BLOCK = re.compile(
    r">>>\s+\[Device Install \(Hardware initiated\)\s*-\s*"
    r"(?P<inst>[^\]]+)\]\s*\n"
    r">>>\s+Section start (?P<ts>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d+)",
    re.I)
_INSTID = re.compile(r"(USBSTOR|USB)\\[^\\]+\\([^\\\s\]]+)", re.I)


def _iso(s: str) -> str:
    try:
        return datetime.strptime(s.split(".")[0], "%Y/%m/%d %H:%M:%S") \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ""


def first_seen(text: str) -> dict[str, str]:
    """serial (last path component of the device instance) -> earliest ISO."""
    out: dict[str, str] = {}
    for m in _BLOCK.finditer(text):
        inst = m.group("inst")
        ts = _iso(m.group("ts"))
        if not ts:
            continue
        im = _INSTID.search(inst)
        serial = im.group(2) if im else inst.strip().split("\\")[-1]
        serial = re.sub(r"&\d+$", "", serial.strip())
        if serial not in out or ts < out[serial]:
            out[serial] = ts
    return out
