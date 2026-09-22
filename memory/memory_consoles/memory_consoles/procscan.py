"""Find EPROCESS-shaped regions whose ImageFileName field is an exact,
literal match for a known console-host/shell process name.

Unlike a field-offset guess, an exact literal-string match within a
plausible window is effectively unambiguous - no separate verification
step is needed the way the other tools in this batch need one for a
guessed numeric offset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PROC_TAG = re.compile(rb"Proc")
# Kept conservative on purpose: a window wide enough to comfortably
# reach ImageFileName's various cited offsets, but not so wide it
# reaches into an ADJACENT process's own pool block and reports the
# wrong name for this "Proc" tag hit - a real cross-contamination bug
# caught via the GUI screenshot during development, fixed here.
_WINDOW = 0x340
_NAMES = (b"conhost.exe", b"cmd.exe", b"powershell.exe", b"pwsh.exe")
_NAME_FIELD_LEN = 15


def _find_name(window: bytes) -> str | None:
    best_idx, best_name = None, None
    for name in _NAMES:
        idx = window.find(name)
        if idx == -1:
            continue
        # ImageFileName is a fixed 15-byte, NUL-padded ASCII field -
        # require the byte(s) right after the match to be NUL or the
        # field boundary, not more trailing letters (avoid matching
        # "conhost.exemplary" or similar coincidental substrings)
        end = idx + len(name)
        if end < len(window) and window[end] not in (0, ) and \
                (end - idx) < _NAME_FIELD_LEN:
            continue
        if best_idx is None or idx < best_idx:
            best_idx, best_name = idx, name
    return best_name.decode("ascii") if best_name else None


@dataclass
class ProcessHit:
    phys_offset: int
    name: str


def scan(img, *, progress=None) -> list[ProcessHit]:
    hits: list[ProcessHit] = []
    seen: set[tuple[int, str]] = set()
    scanned = 0
    for base, block in img.stream_runs():
        for m in _PROC_TAG.finditer(block):
            t = m.start()
            window = block[t:t + _WINDOW]
            name = _find_name(window)
            if name is None:
                continue
            key = (base + t, name)
            if key in seen:
                continue
            seen.add(key)
            hits.append(ProcessHit(phys_offset=base + t, name=name))
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)
    return hits
