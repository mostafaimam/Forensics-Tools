"""Windows: collect the files that contain memory (no driver-free RAM dump)."""

from __future__ import annotations

import glob
import os
from pathlib import Path

# (relative-to-root path or glob, category, note)
_TARGETS = [
    ("pagefile.sys", "page file", "paged-out memory"),
    ("swapfile.sys", "swap file", "modern-app suspended memory"),
    ("hiberfil.sys", "hibernation", "compressed full-RAM snapshot (if hibernated)"),
    ("Windows/MEMORY.DMP", "crash dump", "kernel/complete memory dump"),
    ("Windows/Minidump/*.dmp", "minidump", "bugcheck minidumps"),
    ("Windows/LiveKernelReports/*.dmp", "live kernel dump", ""),
    ("Users/*/AppData/Local/CrashDumps/*.dmp", "app crash dump", ""),
    ("ProgramData/Microsoft/Windows/WER/ReportArchive/**/*.dmp",
     "WER dump", ""),
]


def _candidates(root: Path):
    for pattern, category, note in _TARGETS:
        base = str(root / pattern)
        if any(c in pattern for c in "*?["):
            for hit in glob.glob(base, recursive=True):
                yield Path(hit), category, note
        else:
            p = root / pattern
            if p.exists():
                yield p, category, note


def enumerate_sources(root: str | None = None) -> list[dict]:
    r = Path(root) if root else Path(os.environ.get("SystemDrive", "C:") + "\\")
    out = []
    for path, category, note in _candidates(r):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        locked = False
        if not root:
            try:
                with path.open("rb") as fh:
                    fh.read(1)
            except (PermissionError, OSError):
                locked = True
        out.append({"path": str(path), "category": category, "note": note,
                    "size": size, "locked": locked})
    return out
