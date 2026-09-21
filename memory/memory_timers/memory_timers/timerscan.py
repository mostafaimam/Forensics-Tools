"""Structural scan for KTIMER objects (x64) in physical memory.

Layout (all offsets relative to the DISPATCHER_HEADER start):

    0   DISPATCHER_HEADER (24 bytes): Type(1) Signalling(1) Size(1)
        Reserved(1) SignalState(4) WaitListHead.Flink(8) .Blink(8)
    24  DueTime (8, ULARGE_INTEGER FILETIME-relative or interrupt-relative)
    32  TimerListEntry.Flink (8)
    40  TimerListEntry.Blink (8)
    48  Dpc (8, nullable pointer)
    56  Period (4) - pre-Windows-8 layout
    56  Processor (4) + 60 Period (4) - Windows-8+ layout (an extra field
        was inserted here; both offsets are tried, see _pick_period)

``Type`` is a documented, stable KOBJECTS enum value: 8 =
TimerNotificationObject, 9 = TimerSynchronizationObject. Every pointer
-shaped field is checked for looking like a canonical x64 kernel
-space address (or NULL) rather than trusted blindly.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_HEADER_SIZE = 24
_MIN_SIZE = _HEADER_SIZE + 8 + 16 + 8 + 4      # through Period, no Processor
_TIMER_TYPES = (8, 9)
_SIZE_FIELD_RANGE = range(8, 25)
_DAY_MS = 24 * 3600 * 1000


def _is_kernel_ptr(v: int) -> bool:
    return v == 0 or (v >> 48) == 0xFFFF


def _pick_period(no_proc: int, with_proc: int | None) -> tuple[int, str]:
    def plausible(p):
        return 0 <= p <= _DAY_MS
    if plausible(no_proc) and not (with_proc is not None and
                                   plausible(with_proc) and with_proc != 0):
        return no_proc, "pre-Win8 layout"
    if with_proc is not None and plausible(with_proc):
        return with_proc, "Win8+ layout"
    if plausible(no_proc):
        return no_proc, "pre-Win8 layout"
    return no_proc, "uncertain (neither offset looked plausible)"


@dataclass
class TimerHit:
    phys_offset: int
    timer_type: str
    signal_state: int
    due_time: int
    dpc: int
    period_ms: int
    period_confidence: str


def _try_at(block: bytes, off: int) -> TimerHit | None:
    if off + _MIN_SIZE > len(block):
        return None
    type_b = block[off]
    if type_b not in _TIMER_TYPES:
        return None
    size_b = block[off + 2]
    if size_b not in _SIZE_FIELD_RANGE:
        return None
    signal_state = struct.unpack_from("<i", block, off + 4)[0]
    flink, blink = struct.unpack_from("<QQ", block, off + 8)
    if not (_is_kernel_ptr(flink) and _is_kernel_ptr(blink)):
        return None
    due_time = struct.unpack_from("<Q", block, off + 24)[0]
    tl_flink, tl_blink = struct.unpack_from("<QQ", block, off + 32)
    if not (_is_kernel_ptr(tl_flink) and _is_kernel_ptr(tl_blink)):
        return None
    dpc = struct.unpack_from("<Q", block, off + 48)[0]
    if not _is_kernel_ptr(dpc):
        return None
    period_no_proc = struct.unpack_from("<i", block, off + 56)[0]
    period_with_proc = (struct.unpack_from("<i", block, off + 60)[0]
                        if off + 64 <= len(block) else None)
    period, variant = _pick_period(period_no_proc, period_with_proc)
    return TimerHit(
        phys_offset=off,
        timer_type=("TimerNotificationObject" if type_b == 8
                   else "TimerSynchronizationObject"),
        signal_state=signal_state, due_time=due_time, dpc=dpc,
        period_ms=period, period_confidence=variant)


_CANDIDATE_RE = None


def _candidate_re():
    global _CANDIDATE_RE
    if _CANDIDATE_RE is None:
        import re
        _CANDIDATE_RE = re.compile(rb"[\x08\x09]")
    return _CANDIDATE_RE


def scan_block(block: bytes, base_offset: int = 0) -> list[TimerHit]:
    out = []
    for m in _candidate_re().finditer(block):
        hit = _try_at(block, m.start())
        if hit is not None:
            hit.phys_offset += base_offset
            out.append(hit)
    return out


_OVERLAP = 128


def scan_stream(chunks) -> list[TimerHit]:
    """Scan each overlap-widened buffer in full and de-dupe by absolute
    offset, rather than trying to scan only the "new" prefix - a chunk
    smaller than the overlap window would otherwise let a candidate
    near a boundary go unscanned every round (the window keeps growing
    without ever covering it) until it finally does, which is simpler
    and always correct at the cost of re-scanning the overlap region a
    few extra times."""
    out = []
    carry = b""
    carry_base = 0
    for base, chunk in chunks:
        buf = carry + chunk
        buf_base = carry_base if carry else base
        out.extend(scan_block(buf, buf_base))
        overlap = min(_OVERLAP, len(buf))
        carry = buf[-overlap:]
        carry_base = buf_base + len(buf) - overlap
    seen = set()
    uniq = []
    for h in out:
        if h.phys_offset not in seen:
            seen.add(h.phys_offset)
            uniq.append(h)
    return uniq
