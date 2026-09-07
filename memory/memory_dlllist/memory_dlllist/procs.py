"""Light Windows process list for attribution: (phys, name, pid, dtb).

Just enough of a ``_EPROCESS`` scan to attach a suspicious memory region to
an owner - the heavy lifting is in ``memory_pslist``.  The per-process
directory-table base is confirmed with the self-referential PML4 entry, the
same trick ``pagemap`` uses for the kernel DTB.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from memory_dlllist.pagemap import Pml4

_TAG_RE = re.compile(rb"Proc")
_WINDOW = 0xE00
_NAME_RE = re.compile(rb"(?<![\x21-\x7e])([\x21-\x7e ]{2,15})\x00")
_KNOWN = (b"System", b"Registry", b"Memory", b"smss.exe", b"csrss.exe",
          b"wininit.exe", b"services.exe", b"lsass.exe", b"svchost.exe",
          b"explorer.exe", b"winlogon.exe")


@dataclass
class Proc:
    phys: int
    name: str
    pid: int
    dtb: int

    @property
    def pml4(self):
        return Pml4(self._image, self.dtb)


def scan(image, *, limit: int = 2 << 30) -> list[Proc]:
    out: list[Proc] = []
    seen_dtb: dict[int, Proc] = {}
    scanned = 0
    for base, block in image.stream_runs():
        for m in _TAG_RE.finditer(block):
            t = m.start()
            start = max(0, (t - 4) & ~7)
            win = block[start:t + _WINDOW]
            name = _pick_name(win)
            pid = _pick_pid(win)
            dtb = _pick_dtb(win, image)
            if dtb is None:
                continue
            p = Proc(phys=base + start, name=name, pid=pid, dtb=dtb)
            p._image = image
            if dtb not in seen_dtb or (name and not seen_dtb[dtb].name):
                seen_dtb[dtb] = p
        scanned += len(block)
        if scanned >= limit:
            break
    out = list(seen_dtb.values())
    out.sort(key=lambda p: (p.pid or 1 << 30, p.name))
    return out


def _pick_name(win: bytes) -> str:
    best = b""
    best_score = -1
    for m in _NAME_RE.finditer(win):
        nm = m.group(1)
        s = (3 if nm in _KNOWN else 0) + (2 if nm.lower().endswith(b".exe")
                                          else 0)
        if s > best_score:
            best_score, best = s, nm
    return best.decode("latin-1", "replace") if best else ""


def _pick_pid(win: bytes) -> int:
    for i in range(0, len(win) - 8, 4):
        v = struct.unpack_from("<Q", win, i)[0]
        # a PID is a small multiple of 4 and (unlike a DTB) not page-aligned
        if 0 < v < 0x40000 and v % 4 == 0 and v & 0xFFF:
            return v
    return 0


def _pick_dtb(win: bytes, image) -> int | None:
    tried: set[int] = set()
    for off in range(0, min(len(win), 0x120) - 8, 8):
        cand = struct.unpack_from("<Q", win, off)[0]
        if cand == 0 or cand & 0xFFF or cand > image.phys_size or cand in tried:
            continue
        tried.add(cand)
        if Pml4(image, cand).looks_valid():
            return cand
    return None
