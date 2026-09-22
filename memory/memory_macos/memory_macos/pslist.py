"""Walk XNU's `allproc` BSD LIST given a supplied kernel profile, or
fall back to heuristic comm-string carving. See the package docstring
for the confidence split.

Unlike Linux's circular `tasks` list, BSD's `LIST_HEAD`/`LIST_ENTRY`
convention is **NULL-terminated**: `allproc.lh_first` is the first
`proc*`, and each `proc.p_list.le_next` chains to the next, ending at
NULL - a different structural walk than `memory_linux`'s, not the same
code renamed.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass

_MAX_PROCS = 100_000
_COMM_LEN = 16
_ASCII_PRINTABLE = re.compile(rb"[\x20-\x7e]{2,15}")


class ProfileError(ValueError):
    pass


@dataclass
class Profile:
    direct_map_base: int
    allproc_first_va: int
    p_list_next_offset: int
    p_comm_offset: int
    p_pid_offset: int

    @classmethod
    def load(cls, path: str) -> "Profile":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        def _int(key):
            v = data[key]
            return int(v, 0) if isinstance(v, str) else v

        try:
            return cls(
                direct_map_base=_int("direct_map_base"),
                allproc_first_va=_int("allproc_first_va"),
                p_list_next_offset=data["p_list_next_offset"],
                p_comm_offset=data["p_comm_offset"],
                p_pid_offset=data["p_pid_offset"],
            )
        except KeyError as e:
            raise ProfileError(f"profile missing required field: {e}")


@dataclass
class Proc:
    proc_va: int
    comm: str
    pid: int


def _read_pa(img, pa: int, size: int) -> bytes:
    return img.read_physical(pa, size)


def walk_allproc(img, profile: Profile) -> list[Proc]:
    """A genuine BSD-LIST walk (NULL-terminated), not a signature
    scan - translation is simple direct-map arithmetic."""
    procs: list[Proc] = []
    seen: set[int] = set()
    cur_va = profile.allproc_first_va

    for _ in range(_MAX_PROCS):
        if cur_va == 0:
            break
        if cur_va in seen:
            break          # cycle where BSD LIST guarantees none - stop
        seen.add(cur_va)

        pa = cur_va - profile.direct_map_base
        if pa < 0:
            raise ProfileError(
                f"proc VA {cur_va:#x} is below direct_map_base - wrong "
                f"profile or corrupted list")
        comm_raw = _read_pa(img, pa + profile.p_comm_offset, _COMM_LEN)
        pid_raw = _read_pa(img, pa + profile.p_pid_offset, 4)
        comm = comm_raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        pid = struct.unpack("<i", pid_raw)[0]
        procs.append(Proc(proc_va=cur_va, comm=comm, pid=pid))

        next_raw = _read_pa(img, pa + profile.p_list_next_offset, 8)
        cur_va = struct.unpack("<Q", next_raw)[0]

    return procs


def carve_comm_candidates(img) -> list[str]:
    """Weak fallback with no profile - identical caveat to
    memory_linux's: no way to confirm a hit is inside a real proc."""
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
