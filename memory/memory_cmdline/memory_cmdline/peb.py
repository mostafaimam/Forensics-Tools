"""Reach a process's command line through its PEB.

``_EPROCESS`` carries a user-space ``Peb`` pointer whose offset drifts
between builds, so it is found by scanning the process object for a
page-aligned user pointer that resolves - in that process's address
space - to something shaped like a ``_PEB`` (a ``ProcessParameters``
pointer at +0x20 that also resolves).  From there the
``_RTL_USER_PROCESS_PARAMETERS`` offsets (ImagePathName +0x60, CommandLine
+0x70, CurrentDirectory +0x38, WindowTitle +0xb0, Environment +0x80) have
been stable across Windows 7 - 11 x64.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_USER_MIN = 0x10000
_USER_MAX = 0x7FFFFFFF0000


@dataclass
class ProcParams:
    image_path: str = ""
    command_line: str = ""
    current_dir: str = ""
    dll_path: str = ""
    window_title: str = ""
    environment: dict[str, str] = field(default_factory=dict)
    peb: int = 0
    params: int = 0
    resolved: bool = False


def _is_user(v: int) -> bool:
    return _USER_MIN <= v < _USER_MAX


def _ustr(pml4, addr: int, cap: int = 0x800) -> str:
    try:
        raw = pml4.read(addr, 16)
    except Exception:  # noqa: BLE001
        return ""
    length = struct.unpack_from("<H", raw, 0)[0]
    buf = struct.unpack_from("<Q", raw, 8)[0]
    if not length or length % 2 or length > cap or not _is_user(buf):
        return ""
    data = pml4.read(buf, length)
    try:
        s = data.decode("utf-16-le", "replace").replace("\x00", "").strip()
    except Exception:  # noqa: BLE001
        return ""
    return s


def _environment(pml4, addr: int, cap: int = 0x8000) -> dict[str, str]:
    if not _is_user(addr):
        return {}
    try:
        blob = pml4.read(addr, cap)
    except Exception:  # noqa: BLE001
        return {}
    end = blob.find(b"\x00\x00\x00\x00")
    if end == -1:
        end = len(blob)
    text = blob[:end + 1].decode("utf-16-le", "replace")
    out: dict[str, str] = {}
    for line in text.split("\x00"):
        if "=" in line[1:]:
            k, _, v = line.partition("=")
            if k:
                out[k] = v
    return out


def _looks_like_peb(pml4, addr: int) -> int:
    """Return the ProcessParameters pointer if *addr* looks like a _PEB."""
    try:
        peb = pml4.read(addr, 0x30)
    except Exception:  # noqa: BLE001
        return 0
    if peb[:1] not in (b"\x00", b"\x01"):
        return 0
    image_base = struct.unpack_from("<Q", peb, 0x10)[0]
    pp = struct.unpack_from("<Q", peb, 0x20)[0]
    if not (_is_user(image_base) and _is_user(pp)):
        return 0
    try:
        if pml4.translate(pp) is None:
            return 0
    except Exception:  # noqa: BLE001
        return 0
    return pp


def read_params(img, proc, *, want_env: bool = False) -> ProcParams:
    from memory_cmdline.pagemap import Pml4
    out = ProcParams()
    pml4 = Pml4(img, proc.dtb)
    body = img.read_physical(proc.phys, 0x1400)

    pp = 0
    for off in range(0x200, len(body) - 8, 8):
        v = struct.unpack_from("<Q", body, off)[0]
        if v & 0xFFF or not _is_user(v):
            continue
        try:
            if pml4.translate(v) is None:
                continue
        except Exception:  # noqa: BLE001
            continue
        cand = _looks_like_peb(pml4, v)
        if cand:
            out.peb = v
            pp = cand
            break
    if not pp:
        return out

    out.params = pp
    out.current_dir = _ustr(pml4, pp + 0x38)
    out.dll_path = _ustr(pml4, pp + 0x50, cap=0x2000)
    out.image_path = _ustr(pml4, pp + 0x60)
    out.command_line = _ustr(pml4, pp + 0x70, cap=0x2000)
    out.window_title = _ustr(pml4, pp + 0xB0)
    if want_env:
        env_ptr = struct.unpack_from("<Q", pml4.read(pp + 0x80, 8), 0)[0]
        out.environment = _environment(pml4, env_ptr)
    out.resolved = bool(out.command_line or out.image_path)
    return out
