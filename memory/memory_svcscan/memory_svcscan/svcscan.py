"""Recover the Windows service database from ``services.exe`` memory.

The Service Control Manager keeps every service as a ``_SERVICE_RECORD`` in
its own heap, each tagged with the ASCII bytes ``sErv``.  Scanning physical
memory for that tag and reading the record's pointers - resolved through
``services.exe``'s address space - recovers services **without the
registry**, including ones deleted from ``HKLM\\SYSTEM\\...\\Services`` but
still live in the SCM.

The record layout drifts between builds, so the fields are found by
content: a short service key name, a longer display name, a valid service
type and state, and a binary / DLL path.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

_TAG = re.compile(rb"sErv")

_USER_MIN = 0x10000
_USER_MAX = 0x7FFFFFFF0000

_TYPE = {
    0x001: "kernel-driver", 0x002: "fs-driver", 0x004: "adapter",
    0x008: "recognizer-driver", 0x010: "win32-own", 0x020: "win32-share",
    0x050: "user-own", 0x060: "user-share", 0x0d0: "user-svc",
    0x110: "win32-own+interactive", 0x120: "win32-share+interactive",
}
_STATE = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING",
          5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}

_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{2,64}$")
_PATH_HINT = re.compile(r"[\\/]|\.(exe|sys|dll)$|%\w+%|systemroot", re.I)


@dataclass
class Service:
    name: str
    display_name: str
    type: str
    state: str
    binary_path: str
    pid: int
    phys_offset: int
    confidence: str

    def key(self):
        return (self.name.lower(), self.binary_path.lower())


def _wstr(pml4, addr: int, maxlen: int = 0x400) -> str:
    if not (_USER_MIN <= addr < _USER_MAX):
        return ""
    try:
        raw = pml4.read(addr, maxlen)
    except Exception:  # noqa: BLE001
        return ""
    end = raw.find(b"\x00\x00")
    if end % 2:
        end += 1
    if end <= 0:
        return ""
    try:
        s = raw[:end].decode("utf-16-le", "replace")
    except Exception:  # noqa: BLE001
        return ""
    if any(ord(c) < 0x20 and c not in "\t" for c in s):
        return ""
    return s


def _iter_user_ptrs(win: bytes):
    for i in range(0, len(win) - 8, 8):
        v = struct.unpack_from("<Q", win, i)[0]
        if _USER_MIN <= v < _USER_MAX:
            yield i, v


def _parse(win: bytes, tag_off: int, phys: int, pml4) -> Service | None:
    if pml4 is None:
        return None
    # service key name: first user pointer whose target is a short identifier
    name = ""
    name_off = -1
    display = ""
    for off, ptr in _iter_user_ptrs(win):
        s = _wstr(pml4, ptr, 0x88)
        if s and _NAME_RE.match(s) and "\\" not in s and "/" not in s:
            name = s
            name_off = off
            nxt = struct.unpack_from("<Q", win, off + 8)[0] \
                if off + 16 <= len(win) else 0
            if _USER_MIN <= nxt < _USER_MAX:
                display = _wstr(pml4, nxt, 0x200)
            break
    if not name:
        return None

    # type + state: u32s in the window with valid values
    svc_type = state = ""
    for i in range(name_off, min(len(win), name_off + 0x60) - 4, 4):
        v = struct.unpack_from("<I", win, i)[0]
        if not svc_type and v in _TYPE:
            svc_type = _TYPE[v]
        elif not state and 1 <= v <= 7:
            state = _STATE[v]
    if not svc_type:
        for i in range(max(0, name_off - 0x20), name_off, 4):
            v = struct.unpack_from("<I", win, i)[0]
            if v in _TYPE:
                svc_type = _TYPE[v]
                break

    # binary path / ServiceDll
    binary = ""
    for off, ptr in _iter_user_ptrs(win):
        if off == name_off:
            continue
        s = _wstr(pml4, ptr, 0x400)
        if s and _PATH_HINT.search(s) and len(s) > 3:
            binary = s
            break

    # controlling process id (skip values that are really the type / state)
    pid = 0
    for i in range(name_off + 0x10, min(len(win), name_off + 0x90) - 4, 4):
        v = struct.unpack_from("<I", win, i)[0]
        if 0x40 <= v < 0x40000 and v % 4 == 0 and v not in _TYPE:
            pid = v
            break

    conf = "low"
    if name and (svc_type or state):
        conf = "medium"
    if name and svc_type and state and binary:
        conf = "high"

    return Service(name=name, display_name=display or name,
                   type=svc_type or "?", state=state or "?",
                   binary_path=binary, pid=pid, phys_offset=phys,
                   confidence=conf)


def scan(img, *, progress=None) -> list[Service]:
    from memory_svcscan.pagemap import Pml4
    from memory_svcscan.procs import scan as proc_scan

    pml4 = None
    for p in proc_scan(img):
        if p.name.lower() == "services.exe":
            pml4 = Pml4(img, p.dtb)
            break
    if pml4 is None:
        # fall back to any process DTB (kernel half is shared; SCM strings are
        # user-mode though, so this rarely helps - but try)
        procs = proc_scan(img)
        if procs:
            pml4 = Pml4(img, procs[0].dtb)

    found: list[Service] = []
    scanned = 0
    for base, block in img.stream_runs():
        for m in _TAG.finditer(block):
            t = m.start()
            win = block[max(0, t - 0x40):t + 0x80]
            local_tag = min(t, 0x40)
            svc = _parse(win, local_tag, base + max(0, t - 0x40), pml4)
            if svc:
                found.append(svc)
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)

    best: dict = {}
    for s in found:
        k = s.key()
        if k not in best or _rank(s) > _rank(best[k]):
            best[k] = s
    return sorted(best.values(), key=lambda s: s.name.lower())


def _rank(s: Service) -> int:
    return {"high": 3, "medium": 2, "low": 1}[s.confidence]
