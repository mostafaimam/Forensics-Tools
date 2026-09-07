r"""Synthetic Windows RAM image with a full image-VAD -> file-name chain.

Physical layout (one LiME range from physical 0):

    0x01000  kernel PML4 (kernel DTB)      0x02..0x04 kernel PDPT/PD/PT
    0x05000  process PML4                  0x06..0x08 user PDPT/PD/PT
    0x10000  "services.exe" _EPROCESS-ish object (carries the process DTB)
    0x11000  Vad  pool alloc  #1  (ntdll.dll, \System32\)
    0x12000    _SUBSECTION #1
    0x13000    _CONTROL_AREA #1
    0x14000    _FILE_OBJECT #1
    0x15000    file-name buffer #1
    0x16000  Vad  pool alloc  #2  (evil.dll, \Users\..\Temp\)
    0x17..0x1a  its _SUBSECTION / _CONTROL_AREA / _FILE_OBJECT / name buffer
    0x1b000  Vadl pool alloc #3  (executable image, no resolvable file)
    0x1c000  mapped image content for VAD #1  (VA 0x7ffb00000000)
    0x1d000  mapped image content for VAD #2  (VA 0x1e0000000)
    0x1e000  mapped image content for VAD #3  (VA 0x400000)
"""

from __future__ import annotations

import struct

PAGE = 0x1000
KBASE = 0xFFFFF80000000000
RW = 3

P_KPML4 = 1
P_PPML4 = 5
P_SYSTEM = 0x10
N_PAGES = 0x100

VA_NTDLL = 0x7FFB00000000
VA_EVIL = 0x1E0000000
VA_NOFILE = 0x400000

NTDLL_PATH = "\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll"
EVIL_PATH = ("\\Device\\HarddiskVolume2\\Users\\bob\\AppData\\Local\\Temp\\"
             "evil.dll")


def _idx(va, lvl):
    return (va >> (39 - 9 * lvl)) & 0x1FF


def kva(page):
    return KBASE + (page - P_SYSTEM) * PAGE


class Builder:
    def __init__(self):
        self.mem = bytearray(N_PAGES * PAGE)
        self._next = 0x11
        self._kernel_tables()
        self._process_pml4()
        self._system_object()

    # -- infra --------------------------------------------------
    def alloc(self):
        p = self._next
        self._next += 1
        return p

    def _kernel_tables(self):
        m = self.mem
        struct.pack_into("<Q", m, P_KPML4 * PAGE + _idx(KBASE, 0) * 8,
                         2 * PAGE | RW)
        struct.pack_into("<Q", m, P_KPML4 * PAGE + 0x1ED * 8, P_KPML4 * PAGE | RW)
        struct.pack_into("<Q", m, 2 * PAGE, 3 * PAGE | RW)
        struct.pack_into("<Q", m, 3 * PAGE, 4 * PAGE | RW)
        for i in range(N_PAGES - P_SYSTEM):
            struct.pack_into("<Q", m, 4 * PAGE + i * 8,
                             (P_SYSTEM + i) * PAGE | RW)

    def _process_pml4(self):
        m = self.mem
        struct.pack_into("<Q", m, P_PPML4 * PAGE + 0x1ED * 8, P_PPML4 * PAGE | RW)
        struct.pack_into("<Q", m, P_PPML4 * PAGE + _idx(KBASE, 0) * 8,
                         2 * PAGE | RW)
        self._pt_cache = {}

    def map_user(self, va, phys_page):
        m = self.mem
        pml4 = P_PPML4

        def sub(parent, i):
            k = (parent, i)
            if k not in self._pt_cache:
                c = self.alloc()
                self._pt_cache[k] = c
                struct.pack_into("<Q", m, parent * PAGE + i * 8, c * PAGE | RW)
            return self._pt_cache[k]

        pdpt = sub(pml4, _idx(va, 0))
        pd = sub(pdpt, _idx(va, 1))
        pt = sub(pd, _idx(va, 2))
        struct.pack_into("<Q", m, pt * PAGE + _idx(va, 3) * 8,
                         phys_page * PAGE | RW)

    def _system_object(self):
        m = self.mem
        off = P_SYSTEM * PAGE
        m[off + 0x10:off + 0x14] = b"Proc"
        struct.pack_into("<Q", m, off + 0x20, P_PPML4 * PAGE)   # process DTB
        struct.pack_into("<I", m, off + 0x30, 680)              # PID
        m[off + 0x50:off + 0x5d] = b"services.exe\x00"

    # -- image VAD chain ---------------------------------------
    def unicode_string(self, at_page, at_off, text):
        m = self.mem
        buf_page = self.alloc()
        data = text.encode("utf-16-le")
        m[buf_page * PAGE:buf_page * PAGE + len(data)] = data
        struct.pack_into("<HH", m, at_page * PAGE + at_off, len(data),
                         len(data) + 2)
        struct.pack_into("<Q", m, at_page * PAGE + at_off + 8, kva(buf_page))

    def image_vad(self, va, pages, path=None, prot=7, tag=b"Vad "):
        m = self.mem
        vad = self.alloc()
        vo = vad * PAGE
        m[vo + 4:vo + 8] = tag
        node = vo + 0x10
        svpn = va >> 12
        evpn = svpn + pages - 1
        # Win10 _MMVAD_SHORT: low32 VPNs + high bytes + ULONG flags at +0x30
        struct.pack_into("<I", m, node + 0x18, svpn & 0xFFFFFFFF)
        struct.pack_into("<I", m, node + 0x1C, evpn & 0xFFFFFFFF)
        m[node + 0x20] = (svpn >> 32) & 0xFF
        m[node + 0x21] = (evpn >> 32) & 0xFF
        struct.pack_into("<I", m, node + 0x30, (prot & 0x1F) << 7)
        # VadsProcess pointer near the tail
        struct.pack_into("<Q", m, node + 0x70, kva(P_SYSTEM) + 0x10)

        if path is not None:
            subsec = self.alloc()
            ctrl = self.alloc()
            fobj = self.alloc()
            struct.pack_into("<Q", m, node + 0x38, kva(subsec))     # Subsection
            struct.pack_into("<Q", m, subsec * PAGE, kva(ctrl))     # ControlArea
            struct.pack_into("<Q", m, ctrl * PAGE + 0x40,
                             kva(fobj) | 0x7)                       # FilePointer
            struct.pack_into("<H", m, fobj * PAGE, 5)               # Type = file
            self.unicode_string(fobj, 0x58, path)

        content_pg = self.alloc()
        m[content_pg * PAGE:content_pg * PAGE + 2] = b"MZ"
        self.map_user(va, content_pg)
        return vad

    def lime(self):
        payload = bytes(self.mem)
        return (struct.pack("<IIQQQ", 0x4C694D45, 1, 0, len(payload) - 1, 0)
                + payload)


def build_image() -> bytes:
    b = Builder()
    b.image_vad(VA_NTDLL, 0x40, NTDLL_PATH)
    b.image_vad(VA_EVIL, 0x8, EVIL_PATH)
    b.image_vad(VA_NOFILE, 0x10, path=None, prot=7, tag=b"Vadl")
    return b.lime()
