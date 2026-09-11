"""x64 virtual-to-physical address translation for a Windows RAM image.

No profile or symbol data: the directory-table base (kernel CR3) is found by
scanning for the ``Proc`` pool tag, reading the candidate ``_KPROCESS``
``DirectoryTableBase`` field, and confirming it with the self-referential
PML4 entry (Windows maps the top-level page table into itself at index
0x1ED).  Once the DTB is known, ``Pml4.translate`` walks the four levels and
handles 1 GiB / 2 MiB large pages.
"""

from __future__ import annotations

import re
import struct

_PRESENT = 1
_PS = 0x80                     # large-page bit (PDPT / PD)
_ADDR_MASK = 0x000FFFFFFFFFF000
_SELF_REF_INDEX = 0x1ED        # nt!MmPteBase self-map slot
_KPROCESS_DTB_OFF = 0x28       # _KPROCESS.DirectoryTableBase (stable Win7-11)


class Pml4:
    """A resolved address space rooted at one directory-table base."""

    def __init__(self, image, dtb: int):
        self.image = image
        self.dtb = dtb & ~0xFFF
        self._cache: dict[int, int] = {}

    # -- low level ------------------------------------------------
    def _entry(self, table_phys: int, index: int) -> int:
        raw = self.image.read_physical(table_phys + index * 8, 8)
        return struct.unpack("<Q", raw)[0]

    def translate(self, vaddr: int) -> int | None:
        """Return the physical address for *vaddr*, or ``None`` if unmapped."""
        v = vaddr & ((1 << 48) - 1)
        pml4e = self._entry(self.dtb, (v >> 39) & 0x1FF)
        if not (pml4e & _PRESENT):
            return None
        pdpt = pml4e & _ADDR_MASK
        pdpte = self._entry(pdpt, (v >> 30) & 0x1FF)
        if not (pdpte & _PRESENT):
            return None
        if pdpte & _PS:                                   # 1 GiB page
            return (pdpte & 0x000FFFFFC0000000) | (v & 0x3FFFFFFF)
        pd = pdpte & _ADDR_MASK
        pde = self._entry(pd, (v >> 21) & 0x1FF)
        if not (pde & _PRESENT):
            return None
        if pde & _PS:                                     # 2 MiB page
            return (pde & 0x000FFFFFFFE00000) | (v & 0x1FFFFF)
        pt = pde & _ADDR_MASK
        pte = self._entry(pt, (v >> 12) & 0x1FF)
        if not (pte & _PRESENT):
            return None
        return (pte & _ADDR_MASK) | (v & 0xFFF)

    def read(self, vaddr: int, size: int) -> bytes:
        """Read *size* bytes of virtual memory, zero-filling unmapped pages."""
        out = bytearray()
        got = 0
        while got < size:
            page_off = (vaddr + got) & 0xFFF
            take = min(0x1000 - page_off, size - got)
            phys = self.translate(vaddr + got)
            if phys is None:
                out += b"\x00" * take
            else:
                out += self.image.read_physical(phys, take)
            got += take
        return bytes(out)

    def u64(self, vaddr: int) -> int:
        return struct.unpack("<Q", self.read(vaddr, 8))[0]

    def u32(self, vaddr: int) -> int:
        return struct.unpack("<I", self.read(vaddr, 4))[0]

    # -- validation --------------------------------------------
    def looks_valid(self) -> bool:
        try:
            e = self._entry(self.dtb, _SELF_REF_INDEX)
        except Exception:  # noqa: BLE001
            return False
        return bool(e & _PRESENT) and (e & _ADDR_MASK) == self.dtb


# ---------------------------------------------------------------------------

_PROC_TAG = re.compile(rb"Proc")


def find_kernel_dtb(image, *, limit: int = 512 << 20) -> int | None:
    """Locate the kernel directory-table base by scanning for a System-like
    ``_EPROCESS`` and validating its ``DirectoryTableBase``."""
    hint = image.os_hints.get("directory_table_base")
    if hint:
        p = Pml4(image, hint)
        if p.looks_valid():
            return p.dtb

    scanned = 0
    tried: set[int] = set()
    for base, block in image.stream_runs():
        for m in _PROC_TAG.finditer(block):
            t = m.start()
            start = max(0, (t - 4) & ~7)
            window = block[start:start + 0x400]
            # the _KPROCESS sits a little after the pool header; DTB is one of
            # the first page-aligned, plausible qwords in the window
            for off in range(0, min(len(window), 0x120) - 8, 8):
                cand = struct.unpack_from("<Q", window, off)[0]
                if cand == 0 or cand & 0xFFF or cand > image.phys_size:
                    continue
                if cand in tried:
                    continue
                tried.add(cand)
                pml4 = Pml4(image, cand)
                if pml4.looks_valid():
                    return cand
        scanned += len(block)
        if scanned >= limit:
            break
    return None
