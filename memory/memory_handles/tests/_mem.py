r"""Synthetic RAM image: a kernel address space plus a few _FILE_OBJECTs.

    physical page 1   kernel PML4 (self-ref at 0x1ED)
    physical page 2   PDPT (entry 0 -> page 3)
    physical page 3   PD   (entry 0 -> page 4)
    physical page 4   PT   (entry i -> physical page P_SYSTEM+i)

Physical pages P_SYSTEM.. are therefore reachable at kernel VA
``KBASE + (phys_page - P_SYSTEM) * PAGE`` - a plain linear map, so a
buffer written to any such physical page is resolvable through the
kernel Pml4 with no extra page-table work.
"""

from __future__ import annotations

import struct

PAGE = 0x1000
KBASE = 0xFFFFF80000000000
RW = 3
P_KPML4 = 1
P_SYSTEM = 0x10
N_PAGES = 0x40


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
        # a minimal 'Proc'-tagged blob whose embedded page-aligned qword
        # is the kernel PML4 itself, so find_kernel_dtb() locates it.
        m = self.mem
        eo = 0x100
        m[eo:eo + 4] = b"Proc"
        struct.pack_into("<Q", m, eo + 0x20, P_KPML4 * PAGE)

    def kernel_va(self, phys_page: int) -> int:
        return KBASE + (phys_page - P_SYSTEM) * PAGE

    def write_string_buffer(self, text: str) -> int:
        """Write a UTF-16LE buffer to a fresh kernel-mapped page; return
        its kernel VA."""
        pg = self.alloc()
        data = text.encode("utf-16-le")
        self.mem[pg * PAGE: pg * PAGE + len(data)] = data
        return self.kernel_va(pg)

    def file_object(self, name: str, *, tag_at: int | None = None,
                    body_off: int = 12, name_off: int = 0x58) -> int:
        """Place a 'File' pool tag + a _FILE_OBJECT-shaped body with a
        FileName UNICODE_STRING pointing at a kernel-mapped name buffer.
        Returns the physical offset of the tag."""
        buf_va = self.write_string_buffer(name)
        pg = self.alloc()
        base = pg * PAGE
        tag_off = tag_at if tag_at is not None else 0x20
        self.mem[base + tag_off: base + tag_off + 4] = b"File"
        body = base + tag_off + body_off
        length = len(name) * 2
        struct.pack_into("<HH", self.mem, body + name_off, length, length)
        struct.pack_into("<Q", self.mem, body + name_off + 8, buf_va)
        return base + tag_off

    def plant_file_handle(self, name: str, *, obj_table_off: int = 0x200,
                          shift: int = 20) -> int:
        """Give the (single) synthetic process an ObjectTable pointing at
        a one-level _HANDLE_TABLE with one entry decoding to a
        _FILE_OBJECT whose FileName is `name`. Returns the handle value."""
        # 1. the FileName string buffer
        buf_va = self.write_string_buffer(name)

        # 2. _OBJECT_HEADER + _FILE_OBJECT body (header is page-aligned,
        #    so 16-byte aligned as ObjectPointerBits requires)
        obj_pg = self.alloc()
        oh_va = self.kernel_va(obj_pg)
        body = obj_pg * PAGE + 0x30      # physical offset == VA offset
        length = len(name) * 2
        struct.pack_into("<HH", self.mem, body + 0x58, length, length)
        struct.pack_into("<Q", self.mem, body + 0x58 + 8, buf_va)

        # 3. level-0 handle-table-entry page: one entry at index 0
        lvl0_pg = self.alloc()
        bits44 = (oh_va & 0xFFFFFFFFFFFF) >> 4
        lo = bits44 << shift
        struct.pack_into("<Q", self.mem, lvl0_pg * PAGE, lo)

        # 4. the _HANDLE_TABLE itself: TableCode at +8
        ht_pg = self.alloc()
        table_code = self.kernel_va(lvl0_pg)     # levels = 0
        struct.pack_into("<Q", self.mem, ht_pg * PAGE + 8, table_code)

        # 5. ObjectTable pointer, embedded near the 'Proc' tag at physical
        #    offset `obj_table_off` from the tag structure's own base (0x100)
        struct.pack_into("<Q", self.mem, 0x100 + obj_table_off,
                         self.kernel_va(ht_pg))
        return 0

    def bytes(self) -> bytes:
        return bytes(self.mem)
