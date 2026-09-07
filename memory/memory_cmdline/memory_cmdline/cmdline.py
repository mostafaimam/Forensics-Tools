"""Per-process command line + PEB strings from a Windows RAM dump."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_cmdline import flags as _flags
from memory_cmdline import peb as _peb
from memory_cmdline import procs as _procs


@dataclass
class Row:
    pid: int
    process: str
    image_path: str
    command_line: str
    current_dir: str
    window_title: str
    dll_path: str
    environment: dict = field(default_factory=dict)
    notable: list = field(default_factory=list)
    severity: str = "none"
    resolved: bool = False
    phys_offset: int = 0


def scan(img, *, want_env: bool = False, progress=None) -> list[Row]:
    procs = _procs.scan(img)
    out: list[Row] = []
    for i, p in enumerate(procs):
        if progress:
            progress(i + 1, len(procs))
        try:
            pp = _peb.read_params(img, p, want_env=want_env)
        except Exception:  # noqa: BLE001
            pp = _peb.ProcParams()
        notable = _flags.flag(pp.image_path, pp.command_line)
        out.append(Row(
            pid=p.pid, process=p.name,
            image_path=pp.image_path, command_line=pp.command_line,
            current_dir=pp.current_dir, window_title=pp.window_title,
            dll_path=pp.dll_path, environment=pp.environment,
            notable=notable, severity=_flags.severity(notable),
            resolved=pp.resolved, phys_offset=p.phys))

    sev = {"high": 0, "medium": 1, "low": 2, "none": 3}
    out.sort(key=lambda r: (sev[r.severity], r.pid or 1 << 30))
    return out
