"""Build a synthetic Linux memory image: a direct-mapped physical
region holding a chain of task_struct-shaped entries linked via a
`tasks` list_head, matching a matching profile."""

from __future__ import annotations

import json
import struct

DIRECT_MAP_BASE = 0xFFFF880000000000
TASKS_OFFSET = 0x10
COMM_OFFSET = 0x30
PID_OFFSET = 0x50
TASK_STRIDE = 0x1000


def build(tmp_path, comms: list[str], pids: list[int]):
    n = len(comms)
    mem = bytearray(TASK_STRIDE * (n + 1))

    def task_va(i: int) -> int:
        return DIRECT_MAP_BASE + i * TASK_STRIDE

    for i in range(n):
        base = i * TASK_STRIDE
        next_i = (i + 1) % n
        next_list_head_va = task_va(next_i) + TASKS_OFFSET
        struct.pack_into("<Q", mem, base + TASKS_OFFSET, next_list_head_va)
        comm_bytes = comms[i].encode("ascii")[:15]
        mem[base + COMM_OFFSET:base + COMM_OFFSET + len(comm_bytes)] = \
            comm_bytes
        struct.pack_into("<i", mem, base + PID_OFFSET, pids[i])

    img_path = tmp_path / "linux.mem"
    img_path.write_bytes(bytes(mem))

    profile = {
        "direct_map_base": DIRECT_MAP_BASE,
        "init_task_va": task_va(0),
        "tasks_offset": TASKS_OFFSET,
        "comm_offset": COMM_OFFSET,
        "pid_offset": PID_OFFSET,
    }
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile))
    return img_path, profile_path
