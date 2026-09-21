"""Build a synthetic KTIMER-shaped byte blob for tests."""

from __future__ import annotations

import struct

KERNEL_PTR = 0xFFFFF80012345678
NULL_PTR = 0


def build_ktimer(*, timer_type=8, size=16, signal_state=0,
                 due_time=0xFFFFFFFFFFFFFF00, dpc=KERNEL_PTR,
                 period=1000, with_processor_field=True,
                 flink=KERNEL_PTR, blink=KERNEL_PTR):
    """Returns a 64-byte KTIMER-shaped blob (Win8+ layout, incl. the
    Processor field before Period) unless with_processor_field=False
    (60-byte pre-Win8 layout)."""
    header = struct.pack("<BBBB", timer_type, 0, size, 0)
    header += struct.pack("<i", signal_state)
    header += struct.pack("<QQ", flink, blink)
    assert len(header) == 24
    body = struct.pack("<Q", due_time)                  # DueTime
    body += struct.pack("<QQ", KERNEL_PTR, KERNEL_PTR)  # TimerListEntry
    body += struct.pack("<Q", dpc)                       # Dpc
    if with_processor_field:
        body += struct.pack("<i", 0)                     # Processor
        body += struct.pack("<i", period)                # Period
    else:
        body += struct.pack("<i", period)                # Period
    return header + body


def embed(blob: bytes, payload: bytes, offset: int) -> bytes:
    out = bytearray(blob)
    out[offset:offset + len(payload)] = payload
    return bytes(out)
