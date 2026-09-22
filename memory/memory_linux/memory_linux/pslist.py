"""Walk the `tasks` doubly-linked list given a supplied kernel profile,
or fall back to heuristic comm-string carving. See the package
docstring for the confidence split between the two paths.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass

_MAX_TASKS = 100_000
_COMM_LEN = 16
_ASCII_PRINTABLE = re.compile(rb"[\x20-\x7e]{2,15}")


class ProfileError(ValueError):
    pass


@dataclass
class Profile:
    direct_map_base: int
    init_task_va: int
    tasks_offset: int
    comm_offset: int
    pid_offset: int

    @classmethod
    def load(cls, path: str) -> "Profile":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        try:
            return cls(
                direct_map_base=int(data["direct_map_base"], 0)
                if isinstance(data["direct_map_base"], str)
                else data["direct_map_base"],
                init_task_va=int(data["init_task_va"], 0)
                if isinstance(data["init_task_va"], str)
                else data["init_task_va"],
                tasks_offset=data["tasks_offset"],
                comm_offset=data["comm_offset"],
                pid_offset=data["pid_offset"],
            )
        except KeyError as e:
            raise ProfileError(f"profile missing required field: {e}")


@dataclass
class Task:
    task_struct_va: int
    comm: str
    pid: int


def _read_pa(img, pa: int, size: int) -> bytes:
    return img.read_physical(pa, size)


def walk_task_list(img, profile: Profile) -> list[Task]:
    """A genuine linked-list walk: translation is simple direct-map
    arithmetic (`pa = va - direct_map_base`), valid for kernel
    slab-allocated objects - not a guessed struct offset scan."""
    tasks: list[Task] = []
    seen: set[int] = set()
    start_list_head_va = profile.init_task_va + profile.tasks_offset
    cur_va = start_list_head_va

    for _ in range(_MAX_TASKS):
        pa = cur_va - profile.direct_map_base
        if pa < 0:
            raise ProfileError(
                f"list_head VA {cur_va:#x} is below direct_map_base - "
                f"wrong profile or corrupted list")
        next_raw = _read_pa(img, pa, 8)
        next_va = struct.unpack("<Q", next_raw)[0]
        if next_va == start_list_head_va:
            break
        if next_va in seen or next_va == 0:
            break
        seen.add(next_va)

        task_struct_va = next_va - profile.tasks_offset
        task_pa = task_struct_va - profile.direct_map_base
        comm_raw = _read_pa(img, task_pa + profile.comm_offset, _COMM_LEN)
        pid_raw = _read_pa(img, task_pa + profile.pid_offset, 4)
        comm = comm_raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        pid = struct.unpack("<i", pid_raw)[0]
        tasks.append(Task(task_struct_va=task_struct_va, comm=comm,
                          pid=pid))
        cur_va = next_va

    return tasks


def carve_comm_candidates(img) -> list[str]:
    """Weak fallback with no profile: strings that could plausibly be
    a 16-byte NUL-terminated comm value, with no way to confirm any
    hit is actually inside a task_struct."""
    out: list[str] = []
    seen: set[str] = set()
    for _base, block in img.stream_runs():
        for m in _ASCII_PRINTABLE.finditer(block):
            end = m.end()
            if end >= len(block) or block[end] != 0:
                continue
            s = m.group().decode("ascii")
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
    return out
