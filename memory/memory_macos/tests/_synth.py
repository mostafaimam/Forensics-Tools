"""Build a synthetic macOS memory image: a direct-mapped physical
region holding a NULL-terminated chain of proc-shaped entries linked
via p_list.le_next, matching a matching profile."""

from __future__ import annotations

import json
import struct

DIRECT_MAP_BASE = 0xFFFFFF8000000000
P_LIST_NEXT_OFFSET = 0x08
P_COMM_OFFSET = 0x40
P_PID_OFFSET = 0x60
PROC_STRIDE = 0x1000


def build(tmp_path, comms: list[str], pids: list[int]):
    n = len(comms)
    mem = bytearray(PROC_STRIDE * n)

    def proc_va(i: int) -> int:
        return DIRECT_MAP_BASE + i * PROC_STRIDE

    for i in range(n):
        base = i * PROC_STRIDE
        next_va = proc_va(i + 1) if i + 1 < n else 0   # NULL-terminated
        struct.pack_into("<Q", mem, base + P_LIST_NEXT_OFFSET, next_va)
        comm_bytes = comms[i].encode("ascii")[:15]
        mem[base + P_COMM_OFFSET:base + P_COMM_OFFSET + len(comm_bytes)] \
            = comm_bytes
        struct.pack_into("<i", mem, base + P_PID_OFFSET, pids[i])

    img_path = tmp_path / "macos.mem"
    img_path.write_bytes(bytes(mem))

    profile = {
        "direct_map_base": DIRECT_MAP_BASE,
        "allproc_first_va": proc_va(0),
        "p_list_next_offset": P_LIST_NEXT_OFFSET,
        "p_comm_offset": P_COMM_OFFSET,
        "p_pid_offset": P_PID_OFFSET,
    }
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile))
    return img_path, profile_path
