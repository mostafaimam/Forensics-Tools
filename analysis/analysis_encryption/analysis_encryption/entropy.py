"""Shannon entropy over sampled regions of a file."""

from __future__ import annotations

import math
from pathlib import Path

_SAMPLE = 65536


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def sampled_entropy(path: Path, size: int) -> tuple[float, list[float]]:
    """Entropy of the head, middle and tail samples; returns (min, [samples])."""
    parts = []
    try:
        with path.open("rb") as fh:
            fh.seek(0)
            parts.append(shannon(fh.read(_SAMPLE)))
            if size > _SAMPLE * 3:
                fh.seek(size // 2)
                parts.append(shannon(fh.read(_SAMPLE)))
                fh.seek(max(0, size - _SAMPLE))
                parts.append(shannon(fh.read(_SAMPLE)))
            elif size > _SAMPLE:
                fh.seek(max(0, size - _SAMPLE))
                parts.append(shannon(fh.read(_SAMPLE)))
    except OSError:
        return 0.0, []
    return (min(parts) if parts else 0.0), [round(p, 3) for p in parts]
