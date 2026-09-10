"""Discover .fseventsd logs under a root and parse them."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from macos_fsevents import fsevents as _fse

_SKIP = {"fseventsd-uuid", "no_log", ".DS_Store"}

_WRITABLE = re.compile(r"/(private/tmp|tmp|var/tmp|Users/[^/]+/(Downloads|"
                       r"Library/Caches|\.Trash)|Users/Shared)/", re.I)
_SENSITIVE = re.compile(
    r"(TCC\.db|com\.apple\.LaunchServices\.QuarantineEventsV2|"
    r"\.bash_history|\.zsh_history|\.sh_history|knowledgeC\.db|"
    r"/\.fseventsd/|com\.apple\.XProtect|/var/db/diagnostics/|"
    r"/var/audit/|/private/var/log/|LaunchAgents/|LaunchDaemons/|"
    r"/etc/sudoers|\.ssh/authorized_keys|ASL/)", re.I)


@dataclass
class Result:
    records: list = field(default_factory=list)
    files: int = 0
    errors: list = field(default_factory=list)
    fseventsd_dirs: list = field(default_factory=list)


def _approx(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime, timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return ""


def _flag(rec) -> list[str]:
    out = []
    names = set(rec.flag_names)
    created = names & {"Created", "FolderCreated"}
    removed = names & {"Removed", "FolderRemoved", "LastHardLinkRemoved"}

    if _SENSITIVE.search(rec.path):
        if removed:
            out.append(f"a security / logging artefact was removed "
                       f"({rec.path})")
        elif "Renamed" in names:
            out.append(f"a security / logging artefact was renamed "
                       f"({rec.path})")
        else:
            out.append(f"a security / logging artefact was touched "
                       f"({rec.path})")
    if created and _WRITABLE.search(rec.path):
        out.append("file created in a user-writable / temp path")
    if removed and _WRITABLE.search(rec.path):
        out.append("file removed from a user-writable / temp path")
    if "Mount" in names or "Unmount" in names:
        out.append(f"volume {'mount' if 'Mount' in names else 'unmount'} "
                   f"event")
    return out


def collect(root_str: str, *, dedupe: bool = True) -> Result:
    res = Result()
    root = Path(root_str)

    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for name in (".fseventsd", "System/Volumes/Data/.fseventsd"):
            d = root / name
            if d.is_dir():
                res.fseventsd_dirs.append(str(d))
                files += [f for f in sorted(d.iterdir())
                          if f.is_file() and f.name not in _SKIP]
        if not res.fseventsd_dirs:
            files = [f for f in sorted(root.rglob("*"))
                     if f.is_file() and f.parent.name == ".fseventsd"
                     and f.name not in _SKIP]

    seen: set = set()
    for f in files:
        try:
            raw = f.read_bytes()
        except OSError as e:
            res.errors.append(f"{f}: {e}")
            continue
        res.files += 1
        at = _approx(f)
        for rec in _fse.parse_stream(raw, f.name):
            rec.approx_time = at
            if dedupe:
                key = (rec.path, rec.event_id, rec.flags)
                if key in seen:
                    continue
                seen.add(key)
            rec.notable = _flag(rec)
            res.records.append(rec)

    res.records.sort(key=lambda r: (r.event_id, r.path))
    return res
