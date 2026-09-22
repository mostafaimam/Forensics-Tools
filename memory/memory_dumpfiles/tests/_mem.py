r"""Synthetic RAM image: a kernel address space plus _FILE_OBJECTs, some
with a full SectionObjectPointer -> SharedCacheMap -> VACB chain.

    physical page 1   kernel PML4 (self-ref at 0x1ED)
    physical page 2   PDPT (entry 0 -> page 3)
    physical page 3   PD   (entry 0 -> page 4)
    physical page 4   PT   (entry i -> physical page P_SYSTEM+i)

Physical pages P_SYSTEM.. are reachable at kernel VA
``KBASE + (phys_page - P_SYSTEM) * PAGE`` - a plain linear map.
"""

from __future__ import annotations

import struct

PAGE = 0x1000
KBASE = 0xFFFFF80000000000
RW = 3
P_KPML4 = 1
P_SYSTEM = 0x10
N_PAGES = 0x100  # keep (N_PAGES - P_SYSTEM) under 512: one PT page's limit


def _idx(va, lvl):
    return (va >> (39 - 9 * lvl)) & 0x1FF


class Builder:
    def __init__(self):
        self.mem = bytearray(N_PAGES * PAGE)
        self._next = P_SYSTEM
        self._kernel()
        self._proc_tag()

    def alloc(self):
        p = self._next
        self._next += 1
        return p

    def _kernel(self):
        m = self.mem
        struct.pack_into("<Q", m, P_KPML4 * PAGE + _idx(KBASE, 0) * 8,
                         2 * PAGE | RW)
        struct.pack_into("<Q", m, P_KPML4 * PAGE + 0x1ED * 8,
                         P_KPML4 * PAGE | RW)
        struct.pack_into("<Q", m, 2 * PAGE, 3 * PAGE | RW)
        struct.pack_into("<Q", m, 3 * PAGE, 4 * PAGE | RW)
        for i in range(N_PAGES - P_SYSTEM):
            struct.pack_into("<Q", m, 4 * PAGE + i * 8,
                             (P_SYSTEM + i) * PAGE | RW)

    def _proc_tag(self):
        m = self.mem
        eo = 0x100
        m[eo:eo + 4] = b"Proc"
        struct.pack_into("<Q", m, eo + 0x20, P_KPML4 * PAGE)

    def kernel_va(self, phys_page: int) -> int:
        return KBASE + (phys_page - P_SYSTEM) * PAGE

    def write_string_buffer(self, text: str) -> int:
        pg = self.alloc()
        data = text.encode("utf-16-le")
        self.mem[pg * PAGE: pg * PAGE + len(data)] = data
        return self.kernel_va(pg)

    def write_bytes_page(self, data: bytes) -> int:
        pg = self.alloc()
        self.mem[pg * PAGE: pg * PAGE + len(data)] = data
        return self.kernel_va(pg)

    def vacb(self, base_address_va: int, scm_va: int,
            file_offset: int = 0) -> int:
        pg = self.alloc()
        base = pg * PAGE
        struct.pack_into("<QQQQ", self.mem, base,
                         base_address_va, scm_va, file_offset, 0)
        return self.kernel_va(pg)

    def shared_cache_map(self, vacb_vas: list[int], *,
                         initial_vacbs_off: int = 0x40) -> int:
        pg = self.alloc()
        base = pg * PAGE
        for i, va in enumerate(vacb_vas):
            struct.pack_into("<Q", self.mem,
                             base + initial_vacbs_off + i * 8, va)
        return self.kernel_va(pg)

    def section_object_pointers(self, shared_cache_map_va: int) -> int:
        pg = self.alloc()
        base = pg * PAGE
        struct.pack_into("<QQQ", self.mem, base, 0, shared_cache_map_va, 0)
        return self.kernel_va(pg)

    def file_object(self, name: str, *, tag_at: int | None = None,
                    body_off: int = 12, name_off: int = 0x58,
                    sop_off: int = 0x28,
                    section_object_pointers_va: int | None = None) -> int:
        """Place a 'File' pool tag + a _FILE_OBJECT-shaped body with a
        FileName UNICODE_STRING and (optionally) a SectionObjectPointer
        field. Returns the physical offset of the tag."""
        buf_va = self.write_string_buffer(name)
        pg = self.alloc()
        base = pg * PAGE
        tag_off = tag_at if tag_at is not None else 0x20
        self.mem[base + tag_off: base + tag_off + 4] = b"File"
        body = base + tag_off + body_off
        length = len(name) * 2
        struct.pack_into("<HH", self.mem, body + name_off, length, length)
        struct.pack_into("<Q", self.mem, body + name_off + 8, buf_va)
        if section_object_pointers_va is not None:
            struct.pack_into("<Q", self.mem, body + sop_off,
                             section_object_pointers_va)
        return base + tag_off

    def file_object_with_cache(self, name: str, view_content: bytes,
                               file_offset: int = 0) -> int:
        """A _FILE_OBJECT with a full, self-consistent SectionObject
        Pointers -> SharedCacheMap -> VACB chain pointing at a page
        holding `view_content` (padded/truncated to one page for the
        test)."""
        content_va = self.write_bytes_page(
            view_content[:PAGE].ljust(PAGE, b"\x00"))
        # SharedCacheMap needs to exist before the VACB references it,
        # but the VACB's back-pointer must equal the SharedCacheMap VA -
        # allocate the page first, compute its VA, then fill both.
        scm_pg = self.alloc()
        scm_va = self.kernel_va(scm_pg)
        vacb_va = self.vacb(content_va, scm_va, file_offset)
        struct.pack_into("<Q", self.mem, scm_pg * PAGE + 0x40, vacb_va)
        sop_va = self.section_object_pointers(scm_va)
        return self.file_object(name, section_object_pointers_va=sop_va)

    def bytes(self) -> bytes:
        return bytes(self.mem)
