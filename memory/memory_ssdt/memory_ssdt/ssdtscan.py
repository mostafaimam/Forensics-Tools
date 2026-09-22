"""Scan for SSDT-shaped function-pointer arrays by clustering, not by
locating KeServiceDescriptorTable directly (it's unexported on x64 and
this project has no stable, version-independent way to find it). See
the package docstring for the full reasoning and its limits.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from memory_ssdt.pagemap import Pml4, find_kernel_dtb

_MIN_ENTRIES = 32
_MAX_CLUSTER_SPAN = 32 << 20       # 32 MiB - one plausible kernel image
_STRIDE = 8
_SCAN_CHUNK = 8


def _canonical(v: int) -> bool:
    return v != 0 and (v >> 48) == 0xFFFF


@dataclass
class Candidate:
    phys_offset: int
    entries: list[int]
    cluster_lo: int
    cluster_hi: int
    outliers: list[tuple[int, int]] = field(default_factory=list)


def _find_runs(block: bytes) -> list[tuple[int, list[int]]]:
    """Find maximal runs of consecutive canonical-pointer qwords at
    least _MIN_ENTRIES long."""
    runs = []
    n = len(block) - 8
    i = 0
    while i <= n:
        if i % 8 != 0:
            i += 1
            continue
        run_start = i
        ptrs = []
        while i <= n:
            v = struct.unpack_from("<Q", block, i)[0]
            if not _canonical(v):
                break
            ptrs.append(v)
            i += _STRIDE
        if len(ptrs) >= _MIN_ENTRIES:
            runs.append((run_start, ptrs))
        else:
            i = run_start + 8
    return runs


def _cluster_bounds(ptrs: list[int]) -> tuple[int, int] | None:
    """The tightest window containing at least 90% of `ptrs`, if one
    exists within _MAX_CLUSTER_SPAN."""
    s = sorted(ptrs)
    n = len(s)
    need = max(1, int(n * 0.9))
    best = None
    for i in range(0, n - need + 1):
        lo, hi = s[i], s[i + need - 1]
        if hi - lo <= _MAX_CLUSTER_SPAN:
            if best is None or (hi - lo) < (best[1] - best[0]):
                best = (lo, hi)
    return best


def scan(img, *, verify_mapped: bool = True,
        progress=None) -> list[Candidate]:
    pml4 = None
    if verify_mapped:
        dtb = find_kernel_dtb(img)
        if dtb is not None:
            pml4 = Pml4(img, dtb)

    out: list[Candidate] = []
    scanned = 0
    for base, block in img.stream_runs(chunk=_SCAN_CHUNK << 20):
        for off, ptrs in _find_runs(block):
            bounds = _cluster_bounds(ptrs)
            if bounds is None:
                continue
            lo, hi = bounds
            margin = (hi - lo) // 4 or 0x1000
            outliers = []
            for idx, p in enumerate(ptrs):
                if not (lo - margin <= p <= hi + margin):
                    outliers.append((idx, p))
                    continue
                if pml4 is not None and pml4.translate(p) is None:
                    outliers.append((idx, p))
            out.append(Candidate(phys_offset=base + off, entries=ptrs,
                                 cluster_lo=lo, cluster_hi=hi,
                                 outliers=outliers))
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)
    return out
