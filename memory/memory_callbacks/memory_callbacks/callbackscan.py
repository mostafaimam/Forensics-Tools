"""Scan for small, mostly-NULL kernel callback-array-shaped pointer
tables. See the package docstring for the confidence caveats.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from memory_callbacks.pagemap import Pml4, find_kernel_dtb

_SIZES = (8, 64)                   # commonly-cited callback array sizes
_FLAG_MASK = ~0xF & ((1 << 64) - 1)  # low nibble may be flag bits
_MAX_CLUSTER_SPAN = 32 << 20
_STRIDE = 8


def _canonical(v: int) -> bool:
    return v != 0 and (v >> 48) == 0xFFFF


def _cluster_bounds(ptrs: list[int]) -> tuple[int, int] | None:
    if not ptrs:
        return None
    s = sorted(ptrs)
    n = len(s)
    need = max(1, int(n * 0.9)) if n > 1 else 1
    best = None
    for i in range(0, n - need + 1):
        lo, hi = s[i], s[i + need - 1]
        if hi - lo <= _MAX_CLUSTER_SPAN:
            if best is None or (hi - lo) < (best[1] - best[0]):
                best = (lo, hi)
    return best


@dataclass
class Candidate:
    phys_offset: int
    size: int
    entries: list[int]              # raw values, 0 for unregistered slots
    non_null_indices: list[int] = field(default_factory=list)
    outlier_indices: list[int] = field(default_factory=list)


def _classify(entries: list[int]) -> tuple[bool, list[int]]:
    """(ok, masked_non_null_values) - ok is False if any entry is
    non-zero but not a plausible masked kernel pointer."""
    masked = []
    for v in entries:
        if v == 0:
            continue
        m = v & _FLAG_MASK
        if not _canonical(m):
            return False, []
        masked.append(m)
    return True, masked


def _find_candidates(block: bytes, size: int, *,
                     pml4=None) -> list[tuple[int, list[int]]]:
    """Slide one qword at a time (not non-overlapping): a real array
    preceded by some zero padding can also match at a partial,
    misaligned offset a few qwords early, capturing fewer of its real
    entries. Collapsing every run of overlapping hits down to the one
    with the most non-null entries picks the correctly-aligned window
    instead of locking onto whichever one happened to match first."""
    window_bytes = size * _STRIDE
    n = len(block) - window_bytes
    raw_hits = []
    pos = 0
    while pos <= n:
        raw = struct.unpack_from(f"<{size}Q", block, pos)
        ok, masked = _classify(list(raw))
        if ok and masked:
            raw_hits.append((pos, list(raw), len(masked)))
        pos += _STRIDE

    out = []
    i = 0
    while i < len(raw_hits):
        group_start = raw_hits[i][0]   # fixed - do not drift with `best`
        j = i
        best = raw_hits[i]
        while j + 1 < len(raw_hits) and \
                raw_hits[j + 1][0] - group_start < window_bytes:
            j += 1
            if raw_hits[j][2] > best[2]:
                best = raw_hits[j]
        out.append((best[0], best[1]))
        i = j + 1
    return out


def scan(img, *, verify_mapped: bool = True, sizes=_SIZES,
        progress=None) -> list[Candidate]:
    pml4 = None
    if verify_mapped:
        dtb = find_kernel_dtb(img)
        if dtb is not None:
            pml4 = Pml4(img, dtb)

    out: list[Candidate] = []
    scanned = 0
    for base, block in img.stream_runs(chunk=8 << 20):
        for size in sizes:
            for off, raw in _find_candidates(block, size, pml4=pml4):
                masked = [v & _FLAG_MASK for v in raw if v]
                bounds = _cluster_bounds(masked)
                non_null_idx = [i for i, v in enumerate(raw) if v]
                outlier_idx = []
                if bounds is not None:
                    lo, hi = bounds
                    margin = max((hi - lo) // 4, 0x1000)
                    for i in non_null_idx:
                        m = raw[i] & _FLAG_MASK
                        if not (lo - margin <= m <= hi + margin):
                            outlier_idx.append(i)
                        elif pml4 is not None and \
                                pml4.translate(m) is None:
                            outlier_idx.append(i)
                out.append(Candidate(phys_offset=base + off, size=size,
                                     entries=raw,
                                     non_null_indices=non_null_idx,
                                     outlier_indices=outlier_idx))
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)
    return out
