r"""Synthetic RAM image: services.exe with a handful of _SERVICE_RECORDs.

    0x01000  kernel PML4 (kernel DTB)   0x02..0x04 kernel PDPT/PD/PT
    0x05000  services.exe process PML4  user tables on demand
    0x10000  "services.exe" _EPROCESS object (carries the process DTB)
    ...      one page per service record + one per string buffer, mapped
             into services.exe user space at 0x400000.. / 0x500000..
"""

from __future__ import annotations

import struct

PAGE = 0x1000
KBASE = 0xFFFFF80000000000
RW = 3
P_KPML4 = 1
P_PPML4 = 5
P_SYSTEM = 0x10
N_PAGES = 0x120

_REC_VA = 0x400000
_STR_VA = 0x500000


def _idx(va, lvl):
    return (va >> (39 - 9 * lvl)) & 0x1FF


class Builder:
    def __init__(self, proc_name="services.exe", pid=680):
        self.mem = bytearray(N_PAGES * PAGE)
        self._next = 0x11
        self._pt = {}
        self._rec_va = _REC_VA
        self._str_va = _STR_VA
        self._kernel()
        self._proc(proc_name, pid)

    def alloc(self):
        p = self._next
        self._next += 1
        return p

    def _kernel(self):
        m = self.mem
        struct.pack_into("<Q", m, P_KPML4 * PAGE + _idx(KBASE, 0) * 8, 2 * PAGE | RW)
        struct.pack_into("<Q", m, P_KPML4 * PAGE + 0x1ED * 8, P_KPML4 * PAGE | RW)
        struct.pack_into("<Q", m, 2 * PAGE, 3 * PAGE | RW)
        struct.pack_into("<Q", m, 3 * PAGE, 4 * PAGE | RW)
        for i in range(N_PAGES - P_SYSTEM):
            struct.pack_into("<Q", m, 4 * PAGE + i * 8, (P_SYSTEM + i) * PAGE | RW)

    def _proc(self, name, pid):
        m = self.mem
        struct.pack_into("<Q", m, P_PPML4 * PAGE + 0x1ED * 8, P_PPML4 * PAGE | RW)
        struct.pack_into("<Q", m, P_PPML4 * PAGE + _idx(KBASE, 0) * 8, 2 * PAGE | RW)
        eo = P_SYSTEM * PAGE
        m[eo + 0x10:eo + 0x14] = b"Proc"
        struct.pack_into("<Q", m, eo + 0x20, P_PPML4 * PAGE)
        struct.pack_into("<I", m, eo + 0x30, pid)
        nm = name.encode()
        m[eo + 0x50:eo + 0x50 + len(nm) + 1] = nm + b"\x00"

    def _map(self, va, pg):
        m = self.mem

        def sub(parent, i):
            k = (parent, i)
            if k not in self._pt:
                c = self.alloc()
                self._pt[k] = c
                struct.pack_into("<Q", m, parent * PAGE + i * 8, c * PAGE | RW)
            return self._pt[k]

        pdpt = sub(P_PPML4, _idx(va, 0))
        pd = sub(pdpt, _idx(va, 1))
        pt = sub(pd, _idx(va, 2))
        struct.pack_into("<Q", m, pt * PAGE + _idx(va, 3) * 8, pg * PAGE | RW)

    def _wbuf(self, text) -> int:
        va = self._str_va
        self._str_va += PAGE
        pg = self.alloc()
        data = text.encode("utf-16-le") + b"\x00\x00"
        self.mem[pg * PAGE:pg * PAGE + len(data)] = data
        self._map(va, pg)
        return va

    def service(self, name, display, svc_type, state, binary, pid=0):
        m = self.mem
        va = self._rec_va
        self._rec_va += PAGE
        pg = self.alloc()
        self._map(va, pg)
        o = pg * PAGE
        struct.pack_into("<Q", m, o + 0x10, self._wbuf(name))
        struct.pack_into("<Q", m, o + 0x18, self._wbuf(display))
        m[o + 0x20:o + 0x24] = b"sErv"
        struct.pack_into("<I", m, o + 0x28, svc_type)
        struct.pack_into("<I", m, o + 0x2C, state)
        if binary:
            struct.pack_into("<Q", m, o + 0x38, self._wbuf(binary))
        if pid:
            struct.pack_into("<I", m, o + 0x50, pid)
        return self

    def lime(self):
        payload = bytes(self.mem)
        return (struct.pack("<IIQQQ", 0x4C694D45, 1, 0, len(payload) - 1, 0)
                + payload)


def build_image() -> bytes:
    b = Builder()
    b.service("Schedule", "Task Scheduler", 0x20, 4,
              "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", pid=1044)
    b.service("W32Time", "Windows Time", 0x20, 1,
              "C:\\Windows\\system32\\svchost.exe -k LocalService")
    b.service("Dnscache", "DNS Client", 0x110, 4,
              "C:\\Windows\\System32\\svchost.exe -k NetworkService", pid=1520)
    # an evil one: LOLBin binary from a user-writable path
    b.service("UpdaterSvc", "Windows Update Helper", 0x10, 4,
              "C:\\Users\\Public\\Libraries\\svc.exe", pid=6120)
    # an evil driver
    b.service("a7f3c1d29b", "a7f3c1d29b", 0x1, 4,
              "\\??\\C:\\Windows\\Temp\\drv.sys")
    return b.lime()
