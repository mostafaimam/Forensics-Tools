"""Discover the Tasks tree + SOFTWARE hive under a root and join them."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from windows_tasks import flags as _flags
from windows_tasks import taskcache as _tc
from windows_tasks import taskxml as _xml


@dataclass
class Task:
    name: str = ""
    task_path: str = ""
    source: str = ""
    author: str = ""
    reg_date: str = ""
    description: str = ""
    hidden: bool = False
    enabled: bool = True
    run_as: str = ""
    run_level: str = ""
    logon_type: str = ""
    triggers: list = field(default_factory=list)      # description strings
    actions: list = field(default_factory=list)       # Action
    action_kinds: str = ""
    command_line: str = ""
    registered: str = ""          # from TaskCache DynamicInfo
    last_run: str = ""
    guid: str = ""
    tree_present: bool = True
    registry_only: bool = False
    xml_only: bool = False
    tree_missing: bool = False
    notable: list = field(default_factory=list)


@dataclass
class Result:
    tasks: list = field(default_factory=list)
    xml_files: int = 0
    hive_file: str = ""
    cache_entries: int = 0
    errors: list = field(default_factory=list)


_TASK_SUBPATHS = ("Windows/System32/Tasks", "System32/Tasks", "Tasks")
_HIVE_SUBPATHS = ("Windows/System32/config/SOFTWARE",
                  "System32/config/SOFTWARE", "config/SOFTWARE", "SOFTWARE")


def _find_tasks_dir(root: Path) -> Path | None:
    for rel in _TASK_SUBPATHS:
        p = root / rel
        if p.is_dir():
            return p
    if root.is_dir() and any(root.glob("*.xml")) or \
            (root / "Microsoft").is_dir():
        return root
    return None


def _find_hive(root: Path) -> Path | None:
    for rel in _HIVE_SUBPATHS:
        p = root / rel
        if p.is_file():
            return p
    return None


_SKIP_EXT = {".dll", ".exe", ".sys", ".dat", ".log", ".tmp", ".bak", ".db"}


def _iter_xml(base: Path):
    for p in base.rglob("*"):
        if p.is_file() and p.suffix.lower() not in _SKIP_EXT:
            yield p


def _rel_task_path(base: Path, p: Path) -> str:
    rel = p.relative_to(base).as_posix().replace("/", "\\")
    return "\\" + rel


def analyze(paths) -> Result:
    res = Result()
    for path in paths:
        root = Path(path)
        base = _find_tasks_dir(root)
        hive_path = _find_hive(root)

        cache = _tc.TaskCache()
        if hive_path:
            res.hive_file = str(hive_path)
            cache = _tc.from_hive_file(hive_path)
            res.errors += cache.errors
            res.cache_entries = len(cache.entries)

        by_path: dict[str, Task] = {}
        if base is not None:
            for p in _iter_xml(base):
                try:
                    td = _xml.parse(p)
                except Exception as e:                 # noqa: BLE001
                    res.errors.append(f"{p.name}: {e}")
                    continue
                res.xml_files += 1
                tpath = td.uri or _rel_task_path(base, p)
                t = Task(name=tpath.rstrip("\\").split("\\")[-1],
                         task_path=tpath, source=str(p),
                         author=td.author, reg_date=td.reg_date,
                         description=td.description, hidden=td.hidden,
                         enabled=td.enabled, run_as=td.run_as,
                         run_level=td.run_level, logon_type=td.logon_type,
                         triggers=[tr.description for tr in td.triggers],
                         actions=td.actions,
                         action_kinds=",".join(sorted({a.kind
                                                       for a in td.actions})),
                         command_line=td.command_line())
                by_path[tpath.lower()] = t

        # join TaskCache
        used_guids = set()
        for lp, t in by_path.items():
            gid = cache.tree_paths.get(lp)
            if gid and gid in cache.entries:
                ce = cache.entries[gid]
                t.guid = gid
                t.registered = ce.registered
                t.last_run = ce.last_run
                t.tree_present = ce.tree_present
                t.tree_missing = not ce.tree_present
                used_guids.add(gid)
            elif hive_path:
                t.xml_only = True
            res.tasks.append(t)

        # registry-only tasks
        for gid, ce in cache.entries.items():
            if gid in used_guids or not ce.path:
                continue
            if ce.path.lower() in by_path:
                continue
            t = Task(name=ce.path.rstrip("\\").split("\\")[-1],
                     task_path=ce.path, guid=gid, source=res.hive_file,
                     registered=ce.registered, last_run=ce.last_run,
                     tree_present=ce.tree_present, registry_only=True,
                     tree_missing=not ce.tree_present)
            res.tasks.append(t)

        for t in res.tasks:
            t.notable = _flags.flag({
                "command_line": t.command_line, "actions": t.command_line,
                "task_path": t.task_path, "uri": t.task_path,
                "run_as": t.run_as, "run_level": t.run_level,
                "hidden": t.hidden, "action_kinds": t.action_kinds,
                "registry_only": t.registry_only, "xml_only": t.xml_only,
                "tree_missing": t.tree_missing, "author": t.author,
                "name": t.name,
            })

    res.tasks.sort(key=lambda t: (t.task_path.lower()))
    return res
