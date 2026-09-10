"""Read TaskCache\\{Tree,Tasks} from a SOFTWARE hive."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from windows_tasks.hive import RegistryHive
from windows_tasks.hive.regf import filetime_to_utc

_BASE = (r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache")


@dataclass
class CacheEntry:
    guid: str = ""
    path: str = ""                 # task path e.g. \Microsoft\Windows\...\Foo
    registered: str = ""           # ISO UTC (DynamicInfo)
    last_run: str = ""             # ISO UTC (DynamicInfo)
    tree_present: bool = False
    tree_last_written: str = ""
    tasks_last_written: str = ""
    has_sd: bool = False


@dataclass
class TaskCache:
    entries: dict = field(default_factory=dict)   # guid -> CacheEntry
    tree_paths: dict = field(default_factory=dict)  # path(lower) -> guid
    errors: list = field(default_factory=list)


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def _dynamic_info(blob: bytes) -> tuple[str, str]:
    """DynamicInfo: DWORD version, then FILETIMEs. Offsets 0x04 and 0x0C are
    the most consistently reported (task registered, last run)."""
    if not blob or len(blob) < 0x14:
        return "", ""
    try:
        reg = struct.unpack_from("<Q", blob, 0x04)[0]
        run = struct.unpack_from("<Q", blob, 0x0C)[0]
        return _iso(filetime_to_utc(reg)), _iso(filetime_to_utc(run))
    except struct.error:
        return "", ""


def _walk_tree(key, prefix, out):
    for sub in key.subkeys():
        path = f"{prefix}\\{sub.name}"
        gid = ""
        for v in sub.values():
            if v.name.lower() == "id":
                gid = v.data if isinstance(v.data, str) else \
                    (v.raw_data.decode("utf-16-le", "replace").rstrip("\x00")
                     if v.raw_data else "")
        if gid:
            out[gid] = (path, _iso(sub.last_written))
        _walk_tree(sub, path, out)


def from_hive_bytes(data: bytes) -> TaskCache:
    tc = TaskCache()
    try:
        hive = RegistryHive(data)
    except Exception as e:                       # noqa: BLE001 - vendored lib
        tc.errors.append(f"hive parse failed: {e}")
        return tc

    tree_key = hive.get(f"{_BASE}\\Tree")
    tree_map: dict[str, tuple[str, str]] = {}
    if tree_key is not None:
        try:
            _walk_tree(tree_key, "", tree_map)
        except Exception as e:                   # noqa: BLE001
            tc.errors.append(f"Tree walk failed: {e}")

    tasks_key = hive.get(f"{_BASE}\\Tasks")
    if tasks_key is not None:
        for sub in tasks_key.subkeys():
            guid = sub.name
            ce = CacheEntry(guid=guid,
                            tasks_last_written=_iso(sub.last_written))
            for v in sub.values():
                n = v.name.lower()
                if n == "path":
                    ce.path = v.data if isinstance(v.data, str) else ""
                elif n == "dynamicinfo" and v.raw_data:
                    ce.registered, ce.last_run = _dynamic_info(bytes(v.raw_data))
                elif n == "sd" and v.raw_data:
                    ce.has_sd = True
            if guid in tree_map:
                ce.tree_present = True
                tpath, tlw = tree_map[guid]
                ce.tree_last_written = tlw
                ce.path = ce.path or tpath
            tc.entries[guid] = ce
            if ce.path:
                tc.tree_paths[ce.path.lower()] = guid

    for gid, (path, _lw) in tree_map.items():
        if gid not in tc.entries:
            tc.entries[gid] = CacheEntry(guid=gid, path=path,
                                         tree_present=True)
            tc.tree_paths[path.lower()] = gid
    return tc


def from_hive_file(path) -> TaskCache:
    from pathlib import Path
    return from_hive_bytes(Path(path).read_bytes())
