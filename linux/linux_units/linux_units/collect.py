"""Discover systemd units under a root (mounted image or live system)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from linux_units import flags as _flags
from linux_units.unitfile import UnitData, merge, parse_text

# search order matters: later dirs are lower priority for the *base* unit,
# but /etc overrides /usr.  We resolve per-name.
_UNIT_DIRS = [
    "etc/systemd/system",
    "run/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
]
_USER_DIRS = [
    "etc/systemd/user",
    "usr/lib/systemd/user",
    "lib/systemd/user",
]

_UNIT_SUFFIXES = (".service", ".socket", ".timer", ".target", ".mount",
                  ".automount", ".path", ".slice", ".scope", ".swap")


@dataclass
class Unit:
    name: str
    scope: str = "system"            # system | user
    unit_file: str = ""
    unit_type: str = ""
    description: str = ""
    exec_start: list = field(default_factory=list)
    exec_start_pre: list = field(default_factory=list)
    user: str = ""
    group: str = ""
    dynamic_user: bool = False
    wanted_by: list = field(default_factory=list)
    required_by: list = field(default_factory=list)
    after: list = field(default_factory=list)
    requires: list = field(default_factory=list)
    restart: str = ""
    restart_sec: str = ""
    remain_after_exit: bool = False
    enabled: bool = False
    enabled_via: list = field(default_factory=list)      # symlink locations
    masked: bool = False
    has_install: bool = False
    drop_ins: list = field(default_factory=list)
    mtime_utc: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "name": self.name, "scope": self.scope,
            "type": self.unit_type, "description": self.description,
            "exec_start": " ; ".join(self.exec_start),
            "user": self.user or ("(dynamic)" if self.dynamic_user else ""),
            "wanted_by": ",".join(self.wanted_by),
            "enabled": "masked" if self.masked else
            ("yes" if self.enabled else ""),
            "enabled_via": ",".join(self.enabled_via),
            "restart": self.restart,
            "remain_after_exit": "yes" if self.remain_after_exit else "",
            "has_install": "yes" if self.has_install else "",
            "drop_ins": ",".join(Path(d).name for d in self.drop_ins),
            "unit_file": self.unit_file, "mtime": self.mtime_utc,
            "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    units: list = field(default_factory=list)
    roots: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _mtime(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return ""


def _walk(root: Path, subdirs):
    """Yield (name, [file paths in priority order]) and drop-in dirs."""
    files: dict[str, list[Path]] = {}
    dropins: dict[str, list[Path]] = {}
    enable_links: dict[str, list[str]] = {}
    for i, sub in enumerate(subdirs):
        d = root / sub
        if not d.is_dir():
            continue
        for entry in _iter(d):
            rel = entry
            if rel.name.endswith(_UNIT_SUFFIXES) and rel.is_symlink() \
                    and (".wants" in str(rel.parent) or ".requires"
                         in str(rel.parent)):
                enable_links.setdefault(rel.name, []).append(
                    str(rel.parent.relative_to(root)))
                continue
            if rel.is_dir() and rel.name.endswith(".d"):
                continue
            if rel.suffix in (".conf",) and rel.parent.name.endswith(".d"):
                unit = rel.parent.name[:-2]
                dropins.setdefault(unit, []).append(rel)
                continue
            if rel.name.endswith(_UNIT_SUFFIXES) and (
                    rel.is_file() or rel.is_symlink()):
                files.setdefault(rel.name, [])
                files[rel.name].append(rel)
    return files, dropins, enable_links


def _iter(d: Path):
    for dirpath, dirnames, names in os.walk(d):
        dp = Path(dirpath)
        for n in sorted(dirnames):
            p = dp / n
            if p.is_symlink():
                yield p
        for n in sorted(names):
            yield dp / n


def _build_unit(name: str, paths: list[Path], dropin_paths: list[Path],
                enable_locs: list[str], scope: str, root: Path) -> Unit:
    # the highest-priority (first) file is the effective base
    base_path = paths[0]
    try:
        text = base_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    masked = False
    if base_path.is_symlink():
        try:
            masked = "/dev/null" in os.readlink(base_path).replace("\\", "/")
        except OSError:
            masked = False
    ud = parse_text(text)
    for dp in sorted(dropin_paths):
        try:
            ud = merge(ud, parse_text(dp.read_text(encoding="utf-8",
                                                   errors="replace")))
        except OSError:
            pass

    sect = "Service" if name.endswith(".service") else (
        "Timer" if name.endswith(".timer") else
        "Socket" if name.endswith(".socket") else
        "Mount" if name.endswith(".mount") else "Service")
    install = ud.sections.get("Install", [])
    wanted = []
    for v in ud.get_all("Install", "WantedBy"):
        wanted += v.split()
    required = []
    for v in ud.get_all("Install", "RequiredBy"):
        required += v.split()

    u = Unit(
        name=name, scope=scope,
        unit_file=str(base_path.relative_to(root)),
        unit_type=name.rsplit(".", 1)[-1],
        description=ud.get("Unit", "Description"),
        exec_start=[v for v in ud.get_all(sect, "ExecStart") if v],
        exec_start_pre=[v for v in ud.get_all(sect, "ExecStartPre") if v],
        user=ud.get(sect, "User"),
        group=ud.get(sect, "Group"),
        dynamic_user=ud.get(sect, "DynamicUser").lower() in ("yes", "true",
                                                             "1"),
        wanted_by=wanted, required_by=required,
        after=[x for v in ud.get_all("Unit", "After") for x in v.split()],
        requires=[x for v in ud.get_all("Unit", "Requires")
                  for x in v.split()],
        restart=ud.get(sect, "Restart"),
        restart_sec=ud.get(sect, "RestartSec"),
        remain_after_exit=ud.get(sect, "RemainAfterExit").lower()
        in ("yes", "true", "1"),
        has_install=bool(install) or bool(wanted or required),
        drop_ins=[str(p.relative_to(root)) for p in sorted(dropin_paths)],
        enabled=bool(enable_locs),
        enabled_via=enable_locs,
        masked=masked,
        mtime_utc=_mtime(base_path))
    return u


def collect(root: str) -> Result:
    res = Result()
    r = Path(root)
    if not r.is_dir():
        res.errors.append(f"{root}: not a directory")
        return res
    for scope, subs in (("system", _UNIT_DIRS), ("user", _USER_DIRS)):
        try:
            files, dropins, links = _walk(r, subs)
        except OSError as e:
            res.errors.append(f"{root}: {e}")
            continue
        res.roots.append(f"{root} ({scope})")
        names = set(files) | set(dropins)
        for name in sorted(names):
            paths = files.get(name, [])
            if not paths:
                # drop-in for a unit that lives outside our search - skip base
                continue
            u = _build_unit(name, paths, dropins.get(name, []),
                            links.get(name, []), scope, r)
            u.notable = _flags.flag(u, r)
            res.units.append(u)
    res.units.sort(key=lambda u: (u.scope, u.name))
    return res
