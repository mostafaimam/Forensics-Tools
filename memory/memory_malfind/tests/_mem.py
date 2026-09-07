"""Synthetic Windows RAM image with a private RWX injection and shellcode.

Physical layout (one LiME range from physical 0):

    0x01000  kernel PML4 (kernel DTB)
    0x02000  kernel PDPT   0x03000 kernel PD   0x04000 kernel PT
             -> maps KBASE.. to phys 0x10000..
    0x05000  process PML4 (process DTB) - shares the kernel PDPT, plus a
             user mapping for VA 0x400000 and 0x1a0000
    0x06000  user PDPT   0x07000 user PD   0x08000 user PT
    0x10000  "System" _EPROCESS-ish object carrying the process DTB
    0x11000  VadS pool alloc: private RWX, VA 0x400000..0x41ffff
    0x12000  VadS pool alloc: private RX,  VA 0x1a0000..0x1a3fff  (shellcode)
    0x13000  VadS pool alloc: private RW (not executable - should be ignored)
    0x18000  injected PE header  (mapped at VA 0x400000)
    0x19000  shellcode           (mapped at VA 0x1a0000)
"""

from __future__ import annotations

import struct

PAGE = 0x1000
KBASE = 0xFFFFF80000000000
_RW = 0x3

P_KPML4, P_KPDPT, P_KPD, P_KPT = 1, 2, 3, 4
P_PPML4, P_UPDPT, P_UPD, P_UPT = 5, 6, 7, 8
P_SYSTEM = 0x10
P_VAD_RWX = 0x11
P_VAD_RX = 0x12
P_VAD_RW = 0x13
P_PROC = 0x16
P_PE = 0x18
P_SC = 0x19
N_PAGES = 0x20

VA_PE = 0x400000
VA_SC = 0x1A0000


def _idx(va, level):
    return (va >> (39 - 9 * level)) & 0x1FF


def _kernel_tables(mem):
    struct.pack_into("<Q", mem, P_KPML4 * PAGE + _idx(KBASE, 0) * 8,
                     P_KPDPT * PAGE | _RW)
    struct.pack_into("<Q", mem, P_KPML4 * PAGE + 0x1ED * 8, P_KPML4 * PAGE | _RW)
    struct.pack_into("<Q", mem, P_KPDPT * PAGE, P_KPD * PAGE | _RW)
    struct.pack_into("<Q", mem, P_KPD * PAGE, P_KPT * PAGE | _RW)
    for i in range(N_PAGES - P_SYSTEM):
        struct.pack_into("<Q", mem, P_KPT * PAGE + i * 8,
                         (P_SYSTEM + i) * PAGE | _RW)


def _process_tables(mem):
    # process PML4: self-ref + kernel share + two user mappings
    struct.pack_into("<Q", mem, P_PPML4 * PAGE + 0x1ED * 8, P_PPML4 * PAGE | _RW)
    struct.pack_into("<Q", mem, P_PPML4 * PAGE + _idx(KBASE, 0) * 8,
                     P_KPDPT * PAGE | _RW)
    struct.pack_into("<Q", mem, P_PPML4 * PAGE + _idx(VA_PE, 0) * 8,
                     P_UPDPT * PAGE | _RW)
    struct.pack_into("<Q", mem, P_UPDPT * PAGE + _idx(VA_PE, 1) * 8,
                     P_UPD * PAGE | _RW)
    struct.pack_into("<Q", mem, P_UPD * PAGE + _idx(VA_PE, 2) * 8,
                     P_UPT * PAGE | _RW)
    struct.pack_into("<Q", mem, P_UPT * PAGE + _idx(VA_PE, 3) * 8,
                     P_PE * PAGE | _RW)
    struct.pack_into("<Q", mem, P_UPD * PAGE + _idx(VA_SC, 2) * 8,
                     P_UPT * PAGE | _RW)
    struct.pack_into("<Q", mem, P_UPT * PAGE + _idx(VA_SC, 3) * 8,
                     P_SC * PAGE | _RW)


def _system_object(mem):
    off = P_SYSTEM * PAGE
    struct.pack_into("<Q", mem, off + 8, 0)                 # pad
    mem[off + 0x10:off + 0x14] = b"Proc"
    struct.pack_into("<Q", mem, off + 0x20, P_PPML4 * PAGE)   # process DTB
    struct.pack_into("<Q", mem, off + 0x30, 4)               # PID
    mem[off + 0x50:off + 0x57] = b"System\x00"


def _vad_short(mem, page, start_vpn, end_vpn, prot, private=True):
    off = page * PAGE
    mem[off + 4:off + 8] = b"VadS"
    node = off + 0x10
    struct.pack_into("<I", mem, node + 0x18, start_vpn)
    struct.pack_into("<I", mem, node + 0x1C, end_vpn)
    # Win7 _MMVAD_FLAGS (ULONGLONG): Protection at bit 56, PrivateMemory bit 63
    flags = (prot & 0x1F) << 56
    if private:
        flags |= 1 << 63
    struct.pack_into("<Q", mem, node + 0x20, flags)


def _pe_header(mem, page):
    off = page * PAGE
    mem[off:off + 2] = b"MZ"
    struct.pack_into("<I", mem, off + 0x3C, 0x80)           # e_lfanew
    mem[off + 0x80:off + 0x84] = b"PE\x00\x00"
    struct.pack_into("<H", mem, off + 0x84, 0x8664)         # machine x64


def _shellcode(mem, page):
    off = page * PAGE
    mem[off:off + 16] = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51"


def build_image() -> bytes:
    mem = bytearray(N_PAGES * PAGE)
    _kernel_tables(mem)
    _process_tables(mem)
    _system_object(mem)
    _vad_short(mem, P_VAD_RWX, VA_PE >> 12, (VA_PE >> 12) + 0x1F, 6)   # RWX
    _vad_short(mem, P_VAD_RX, VA_SC >> 12, (VA_SC >> 12) + 3, 3)       # RX
    _vad_short(mem, P_VAD_RW, 0x5000, 0x5003, 4)                       # RW
    _pe_header(mem, P_PE)
    _shellcode(mem, P_SC)
    return _lime(bytes(mem))


_LIME_MAGIC = 0x4C694D45


def _lime(payload: bytes) -> bytes:
    return struct.pack("<IIQQQ", _LIME_MAGIC, 1, 0, len(payload) - 1, 0) + payload
