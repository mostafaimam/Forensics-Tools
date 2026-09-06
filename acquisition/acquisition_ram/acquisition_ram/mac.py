"""macOS: collect memory-bearing files (no driver-free RAM dump under SIP)."""

from __future__ import annotations

import glob
from pathlib import Path

_TARGETS = [
    ("private/var/vm/sleepimage", "hibernation", "full-RAM sleep snapshot"),
    ("private/var/vm/swapfile*", "swap file", "paged-out memory"),
    ("cores/*", "core dump", "process core dumps (if enabled)"),
    ("Library/Logs/DiagnosticReports/*.panic", "kernel panic", ""),
    ("Library/Logs/DiagnosticReports/*.ips", "diagnostic report", ""),
]


def enumerate_sources(root: str | None = None) -> list[dict]:
    r = Path(root) if root else Path("/")
    out = []
    for pattern, category, note in _TARGETS:
        base = str(r / pattern)
        hits = glob.glob(base) if any(c in pattern for c in "*?[") \
            else ([base] if Path(base).exists() else [])
        for hit in hits:
            p = Path(hit)
            try:
                size = p.stat().st_size
            except OSError:
                continue
            locked = False
            if not root:
                try:
                    with p.open("rb") as fh:
                        fh.read(1)
                except (PermissionError, OSError):
                    locked = True
            out.append({"path": str(p), "category": category, "note": note,
                        "size": size, "locked": locked})
    return out
