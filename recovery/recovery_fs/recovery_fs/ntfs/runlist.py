"""Decode an NTFS non-resident attribute data-run list.

Each run: a header byte where the low nibble is the byte-count of the run
*length* field and the high nibble is the byte-count of the run *offset*
field.  The offset is signed and relative to the previous run's LCN.  A run
with a zero-length offset field is *sparse* (unallocated) - its bytes are
zero.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Run:
    lcn: int | None      # None => sparse
    clusters: int


def decode_runlist(data: bytes) -> list[Run]:
    runs: list[Run] = []
    i = 0
    prev_lcn = 0
    n = len(data)
    while i < n:
        header = data[i]
        i += 1
        if header == 0:
            break
        len_size = header & 0x0F
        off_size = (header >> 4) & 0x0F
        if len_size == 0 or i + len_size + off_size > n:
            break
        length = int.from_bytes(data[i:i + len_size], "little", signed=False)
        i += len_size
        if off_size == 0:
            runs.append(Run(None, length))
            continue
        offset = int.from_bytes(data[i:i + off_size], "little", signed=True)
        i += off_size
        prev_lcn += offset
        runs.append(Run(prev_lcn, length))
    return runs


def total_clusters(runs: list[Run]) -> int:
    return sum(r.clusters for r in runs)
