"""Tie image loading, structural scanning, and field decoding together."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from memory_timers.loader import MemoryImage, MemoryImageError
from memory_timers.timerscan import scan_stream

COLUMNS = ["phys_offset", "timer_type", "state", "due_time",
          "period_ms", "period_confidence", "dpc", "source"]

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_LO = datetime(2000, 1, 1, tzinfo=timezone.utc)
_HI = datetime(2100, 1, 1, tzinfo=timezone.utc)


def _decode_due_time(raw_u64: int) -> str:
    signed = struct.unpack("<q", struct.pack("<Q", raw_u64))[0]
    if signed < 0:
        ms = -signed / 10_000
        return f"relative +{ms:.0f}ms"
    try:
        dt = _FT_EPOCH + timedelta(microseconds=raw_u64 / 10)
    except (OverflowError, OSError):
        return f"absolute (unparseable, raw={raw_u64:#x})"
    if _LO <= dt <= _HI:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ") + " (absolute)"
    return f"absolute (out of plausible range, raw={raw_u64:#x})"


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def scan_image(image_path: str) -> Result:
    res = Result()
    try:
        with MemoryImage(image_path) as img:
            hits = scan_stream(img.stream_runs())
    except (MemoryImageError, OSError) as e:
        res.warnings.append(f"{image_path}: {e}")
        return res

    for h in hits:
        res.rows.append({
            "phys_offset": hex(h.phys_offset),
            "timer_type": h.timer_type,
            "state": "signaled" if h.signal_state else "not-signaled",
            "due_time": _decode_due_time(h.due_time),
            "period_ms": h.period_ms,
            "period_confidence": h.period_confidence,
            "dpc": hex(h.dpc) if h.dpc else "",
            "source": image_path,
        })
    if not res.rows:
        res.warnings.append("no structurally-plausible KTIMER found "
                            "(x64 images only in v0.1)")
    return res
