"""Orchestration: scan, flag, sort."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_svcscan import flags as _flags
from memory_svcscan import svcscan as _svc


@dataclass
class Row:
    name: str
    display_name: str
    type: str
    state: str
    binary_path: str
    pid: int
    notable: list = field(default_factory=list)
    severity: str = "none"
    confidence: str = "low"
    phys_offset: int = 0


def scan(img, *, progress=None) -> list[Row]:
    out: list[Row] = []
    for s in _svc.scan(img, progress=progress):
        notable = _flags.flag(s.name, s.binary_path, s.type, s.state)
        out.append(Row(
            name=s.name, display_name=s.display_name, type=s.type,
            state=s.state, binary_path=s.binary_path, pid=s.pid,
            notable=notable, severity=_flags.severity(notable),
            confidence=s.confidence, phys_offset=s.phys_offset))
    sev = {"high": 0, "medium": 1, "low": 2, "none": 3}
    out.sort(key=lambda r: (sev[r.severity], r.name.lower()))
    return out
