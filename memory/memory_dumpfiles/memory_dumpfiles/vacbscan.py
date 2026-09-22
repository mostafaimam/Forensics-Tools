"""Pool-tag scan for _FILE_OBJECT, then a self-verifying walk to any
still-resident cached file content via the Cache Manager's VACB chain.

See the package docstring for why each step scans a plausible offset
window instead of trusting one hardcoded field offset.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from memory_dumpfiles.pagemap import Pml4, find_kernel_dtb

_TAG = re.compile(rb"File")
_NAME_OFFS = (0x58, 0x60, 0x50, 0x40, 0x68)
_BODY_OFFS = (12, 8, 16, 4)

_SOP_OFFS = range(0x18, 0x50, 8)       # candidate SectionObjectPointer offs
_SCM_WINDOW = range(0x00, 0x108, 8)    # candidate InitialVacbs[0] offs
_VACB_COUNT = 4
_VACB_SIZE = 32
_VACB_VIEW_SIZE = 0x40000              # 256 KiB per VACB


def _canonical(v: int) -> bool:
    return v == 0 or (v >> 48) == 0xFFFF


def _wstr(pml4, buf_va: int, length: int) -> str:
    if not (0 < length <= 2048) or length % 2:
        return ""
    try:
        raw = pml4.read(buf_va, length)
        return raw.decode("utf-16-le", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _try_name(pml4, block: bytes, body_local: int) -> str:
    for off in _NAME_OFFS:
        if body_local + off + 16 > len(block):
            continue
        length, maxlen = struct.unpack_from("<HH", block, body_local + off)
        buf = struct.unpack_from("<Q", block, body_local + off + 8)[0]
        if not (0 < length <= maxlen <= 2048) or not _canonical(buf):
            continue
        name = _wstr(pml4, buf, length)
        if name and "\\" in name and all(0x20 <= ord(c) or c == "\t"
                                         for c in name):
            return name
    return ""


@dataclass
class Vacb:
    va: int
    base_address: int
    file_offset: int


@dataclass
class FileHit:
    name: str
    file_object_phys: int
    section_object_pointers_va: int = 0
    shared_cache_map_va: int = 0
    vacbs: list[Vacb] = field(default_factory=list)


def _find_shared_cache_map(pml4, sop_va: int) -> int | None:
    try:
        block = pml4.read(sop_va, 24)
    except Exception:  # noqa: BLE001
        return None
    data_section, shared_cache_map, image_section = \
        struct.unpack("<QQQ", block)
    if shared_cache_map and _canonical(shared_cache_map) and \
            _canonical(data_section) and _canonical(image_section):
        return shared_cache_map
    return None


def _find_vacbs(pml4, scm_va: int) -> list[Vacb]:
    try:
        window = pml4.read(scm_va, 0x108 + _VACB_COUNT * 8)
    except Exception:  # noqa: BLE001
        return []
    for start in _SCM_WINDOW:
        ptrs = struct.unpack_from("<QQQQ", window, start)
        if not all(_canonical(p) for p in ptrs):
            continue
        if not any(ptrs):
            continue
        vacbs = []
        for p in ptrs:
            if not p:
                continue
            try:
                vblock = pml4.read(p, _VACB_SIZE)
            except Exception:  # noqa: BLE001
                continue
            base_address, back_ptr, file_offset, _rest = \
                struct.unpack("<QQQQ", vblock)
            if back_ptr != scm_va:
                continue          # self-reference check failed
            if not _canonical(base_address) or base_address == 0:
                continue
            vacbs.append(Vacb(p, base_address, file_offset))
        if vacbs:
            return vacbs
    return []


def scan(img, *, progress=None) -> list[FileHit]:
    dtb = find_kernel_dtb(img)
    if dtb is None:
        return []
    pml4 = Pml4(img, dtb)
    hits: list[FileHit] = []
    scanned = 0
    for base, block in img.stream_runs():
        for m in _TAG.finditer(block):
            t = m.start()
            for body_off in _BODY_OFFS:
                name = _try_name(pml4, block, t + body_off)
                if not name:
                    continue
                phys = base + t
                fh = FileHit(name=name, file_object_phys=phys)
                for sop_off in _SOP_OFFS:
                    off = t + body_off + sop_off
                    if off + 8 > len(block):
                        continue
                    sop_va = struct.unpack_from("<Q", block, off)[0]
                    if not sop_va or not _canonical(sop_va):
                        continue
                    scm_va = _find_shared_cache_map(pml4, sop_va)
                    if scm_va is None:
                        continue
                    vacbs = _find_vacbs(pml4, scm_va)
                    if vacbs:
                        fh.section_object_pointers_va = sop_va
                        fh.shared_cache_map_va = scm_va
                        fh.vacbs = vacbs
                        break
                hits.append(fh)
                break
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)
    return hits


def read_cached_view(pml4: Pml4, vacb: Vacb) -> bytes:
    return pml4.read(vacb.base_address, _VACB_VIEW_SIZE)
