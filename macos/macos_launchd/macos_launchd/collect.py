"""Discover every launchd plist under a root and parse it."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from macos_launchd import flags as _flags
from macos_launchd import parse as _parse

_DIRS = [
    "Library/LaunchDaemons", "Library/LaunchAgents",
    "System/Library/LaunchDaemons", "System/Library/LaunchAgents",
    "Users/*/Library/LaunchAgents",
]


@dataclass
class Result:
    jobs: list = field(default_factory=list)
    files: int = 0
    errors: list = field(default_factory=list)


def collect(root_str: str) -> Result:
    res = Result()
    root = Path(root_str)

    if root.is_file():
        _one(root, root.name, res)
        return res

    paths: list[Path] = []
    for d in _DIRS:
        if "*" in d:
            for m in root.glob(d):
                paths += sorted(m.glob("*.plist"))
        else:
            p = root / d
            if p.is_dir():
                paths += sorted(p.glob("*.plist"))

    for p in paths:
        try:
            rel = p.relative_to(root).as_posix()
        except ValueError:
            rel = p.as_posix()
        _one(p, rel, res)
    return res


def _one(p: Path, rel: str, res: Result):
    try:
        data = p.read_bytes()
        mode = p.stat().st_mode
    except OSError as e:
        res.errors.append(f"{p}: {e}")
        return
    res.files += 1
    job = _parse.parse_bytes(data, str(p), rel, mode)
    if job is None:
        res.errors.append(f"{p}: not a valid plist / job")
        return
    job.notable = _flags.flag(job)
    res.jobs.append(job)


def sort_jobs(jobs):
    jobs.sort(key=lambda j: (j.scope, j.label or j.filename))
    return jobs
