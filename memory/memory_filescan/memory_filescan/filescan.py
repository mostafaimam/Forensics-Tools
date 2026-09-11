"""Pool-tag scan for _FILE_OBJECT, resolved through the kernel page tables."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from memory_filescan.pagemap import Pml4, find_kernel_dtb

_TAG = re.compile(rb"File")
_KERNEL = 0xFFFF000000000000
_NAME_OFFS = (0x58, 0x60, 0x50, 0x40, 0x68)
_BODY_OFFS = (12, 8, 16, 4)


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


def _read_unicode_string(block: bytes, off: int):
    """Read a (Length, MaximumLength, Buffer) UNICODE_STRING physically -
    the _FILE_OBJECT body is pool memory and sits contiguously in
    physical RAM the same way it does on disk-backed pool pages."""
    if off < 0 or off + 16 > len(block):
        return None
    length, maxlen = struct.unpack_from("<HH", block, off)
    buf = struct.unpack_from("<Q", block, off + 8)[0]
    if not (0 < length <= maxlen <= 2048):
        return None
    if buf & _KERNEL != _KERNEL and not (0x10000 <= buf < 0x7FFFFFFF0000):
        return None
    return length, buf


def _try_name(pml4, block: bytes, body_local: int) -> str:
    for off in _NAME_OFFS:
        got = _read_unicode_string(block, body_local + off)
        if not got:
            continue
        length, buf = got
        name = _wstr(pml4, buf, length)
        if name and "\\" in name:
            return name
    return ""


@dataclass
class FileHit:
    phys: int
    name: str
    device: str

    def row(self) -> dict:
        return {"name": self.name, "device": self.device,
                "phys_offset": f"{self.phys:#x}"}


def _device_of(name: str) -> str:
    m = re.match(r"(\\Device\\[^\\]+)\\", name)
    return m.group(1) if m else ""


def scan(img, *, progress=None) -> list[FileHit]:
    dtb = find_kernel_dtb(img)
    if dtb is None:
        return []
    pml4 = Pml4(img, dtb)
    found: dict[str, FileHit] = {}
    scanned = 0
    for base, block in img.stream_runs():
        for m in _TAG.finditer(block):
            t = m.start()
            for body_off in _BODY_OFFS:
                name = _try_name(pml4, block, t + body_off)
                if name:
                    key = name.lower()
                    if key not in found:
                        found[key] = FileHit(
                            phys=base + t, name=name, device=_device_of(name))
                    break
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)
    return sorted(found.values(), key=lambda f: f.name.lower())
