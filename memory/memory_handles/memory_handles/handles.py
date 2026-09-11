"""Walk each process's handle table and recover open file handles."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from memory_handles.pagemap import Pml4
from memory_handles.procs import scan as proc_scan

_KERNEL = 0xFFFF000000000000
_OBJTABLE_RANGE = range(0x180, 0x620, 8)
_HANDLE_SHIFTS = (20, 19, 16)      # ObjectPointerBits position has drifted
_NAME_OFFS = (0x58, 0x60, 0x50, 0x40, 0x68)
_ENTRY_SIZE = 16
_MAX_LEVEL0 = 0x1000 // _ENTRY_SIZE


def _u64(pml4, va) -> int:
    try:
        return pml4.u64(va)
    except Exception:  # noqa: BLE001
        return 0


def _find_objtable(img, p):
    """Return (pml4, objtable_va, handle_table_base, levels) or
    (pml4, 0, 0, 0) if nothing plausible is found near this _EPROCESS."""
    pml4 = Pml4(img, p.dtb)
    for cand_base in (p.phys, p.phys - 0x10, p.phys - 0x40, p.phys - 0x8):
        if cand_base < 0:
            continue
        for off in _OBJTABLE_RANGE:
            try:
                ptr = int.from_bytes(
                    img.read_physical(cand_base + off, 8), "little")
            except Exception:  # noqa: BLE001
                continue
            if ptr & _KERNEL != _KERNEL or ptr & 0xF:
                continue
            tc = _u64(pml4, ptr + 8)
            if not tc:
                continue
            levels = tc & 7
            base = tc & ~0xF
            if levels <= 2 and base & _KERNEL == _KERNEL and \
                    base & 0xFFF == 0:
                return pml4, ptr, base, levels
    return pml4, 0, 0, 0


def _iter_level0(pml4, base, cap=_MAX_LEVEL0):
    for i in range(cap):
        lo = _u64(pml4, base + i * _ENTRY_SIZE)
        if lo:
            yield i * 4, lo


def _iter_table(pml4, base, levels):
    if levels == 0:
        yield from _iter_level0(pml4, base)
        return
    per_table = 0x1000 // 8
    n = 0
    for i in range(per_table):
        sub = _u64(pml4, base + i * 8)
        if sub & _KERNEL != _KERNEL or sub & 0xFFF:
            continue
        if levels == 1:
            for hv, lo in _iter_level0(pml4, sub):
                yield i * per_table * 4 + hv, lo
        else:
            for j in range(per_table):
                sub2 = _u64(pml4, sub + j * 8)
                if sub2 & _KERNEL != _KERNEL or sub2 & 0xFFF:
                    continue
                for hv, lo in _iter_level0(pml4, sub2):
                    yield n, lo
                    n += 4


def _wstr(pml4, buf_va: int, length: int) -> str:
    if not (0 < length <= 2048) or length % 2:
        return ""
    try:
        raw = pml4.read(buf_va, length)
    except Exception:  # noqa: BLE001
        return ""
    try:
        s = raw.decode("utf-16-le", "replace")
    except UnicodeDecodeError:
        return ""
    if any(0 < ord(c) < 0x20 and c not in "\t" for c in s):
        return ""
    return s


def _try_file_name(pml4, body_va: int) -> str:
    for off in _NAME_OFFS:
        try:
            raw = pml4.read(body_va + off, 16)
        except Exception:  # noqa: BLE001
            continue
        if len(raw) < 16:
            continue
        length, maxlen = struct.unpack_from("<HH", raw, 0)
        buf = struct.unpack_from("<Q", raw, 8)[0]
        if not (0 < length <= maxlen <= 2048):
            continue
        if buf & _KERNEL != _KERNEL and not (0x10000 <= buf < 0x7FFFFFFF0000):
            continue
        name = _wstr(pml4, buf, length)
        if name and "\\" in name:
            return name
    return ""


@dataclass
class Handle:
    pid: int
    process: str
    handle_value: int
    name: str
    notable: list = field(default_factory=list)
    severity: str = "none"

    def row(self) -> dict:
        return {"pid": self.pid, "process": self.process,
                "handle": f"{self.handle_value:#x}", "type": "File",
                "name": self.name, "severity": self.severity,
                "notable": ";".join(self.notable)}


def enumerate_file_handles(img, *, progress=None) -> list[Handle]:
    procs = proc_scan(img)
    out: list[Handle] = []
    for n, p in enumerate(procs):
        if progress:
            progress(n, len(procs))
        pml4, tbl, base, levels = _find_objtable(img, p)
        if not tbl:
            continue
        for hv, lo in _iter_table(pml4, base, levels):
            if not lo:
                continue
            for shift in _HANDLE_SHIFTS:
                bits = lo >> shift
                if not bits:
                    continue
                obj_header = ((bits << 4) & 0xFFFFFFFFFFFF) | _KERNEL
                body = obj_header + 0x30
                name = _try_file_name(pml4, body)
                if name:
                    out.append(Handle(pid=p.pid, process=p.name,
                                      handle_value=hv, name=name))
                    break
    return out
