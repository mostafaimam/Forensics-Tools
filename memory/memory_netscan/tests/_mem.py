"""Build a tiny but internally-consistent synthetic Windows RAM image.

Physical layout (one LiME range from physical 0):

    0x01000  PML4          (this is the DTB)
    0x02000  PDPT
    0x03000  PD
    0x04000  PT            maps VA 0xFFFFF80000000000.. -> phys 0x10000..
    0x10000  "System" _EPROCESS-ish object (name + PID)
    0x11000  _INETAF   (AddressFamily = AF_INET at +0x18)
    0x12000  local _IN_ADDR (an IPv4)
    0x13000  TcpE endpoint
    0x14000  TcpL listener
    0x15000  UdpA endpoint
    0x16000  a Proc pool tag carrying the DTB (for DTB discovery)
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

PAGE = 0x1000
KBASE = 0xFFFFF80000000000
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_PRESENT_RW = 0x3

P_PML4, P_PDPT, P_PD, P_PT = 0x1, 0x2, 0x3, 0x4
P_SYSTEM = 0x10
P_INETAF = 0x11
P_INADDR = 0x12
P_TCPE = 0x13
P_TCPL = 0x14
P_UDPA = 0x15
P_PROC = 0x16
N_PAGES = 0x20


def ft(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc) - _FT_EPOCH).total_seconds()
               * 10_000_000)


def va_of(page: int) -> int:
    return KBASE + (page - P_SYSTEM) * PAGE


def _page_tables(mem: bytearray) -> None:
    idx_pml4 = (KBASE >> 39) & 0x1FF
    struct.pack_into("<Q", mem, P_PML4 * PAGE + idx_pml4 * 8,
                     P_PDPT * PAGE | _PRESENT_RW)
    struct.pack_into("<Q", mem, P_PML4 * PAGE + 0x1ED * 8,
                     P_PML4 * PAGE | _PRESENT_RW)          # self-reference
    struct.pack_into("<Q", mem, P_PDPT * PAGE, P_PD * PAGE | _PRESENT_RW)
    struct.pack_into("<Q", mem, P_PD * PAGE, P_PT * PAGE | _PRESENT_RW)
    for i in range(N_PAGES - P_SYSTEM):
        struct.pack_into("<Q", mem, P_PT * PAGE + i * 8,
                         (P_SYSTEM + i) * PAGE | _PRESENT_RW)


def _system_object(mem: bytearray) -> None:
    off = P_SYSTEM * PAGE
    struct.pack_into("<Q", mem, off + 0x20, 4)              # UniqueProcessId
    mem[off + 0x40:off + 0x47] = b"System\x00"


def _proc_tag_with_dtb(mem: bytearray) -> None:
    off = P_PROC * PAGE
    mem[off + 8:off + 12] = b"Proc"
    struct.pack_into("<Q", mem, off + 0x20, P_PML4 * PAGE)  # the DTB


def _inetaf(mem: bytearray) -> None:
    struct.pack_into("<H", mem, P_INETAF * PAGE + 0x18, 2)  # AF_INET


def _inaddr(mem: bytearray, ip=b"\x0a\x00\x02\x0f") -> None:
    mem[P_INADDR * PAGE:P_INADDR * PAGE + 4] = ip           # 10.0.2.15


def _endpoint(mem: bytearray, page: int, tag: bytes, *, state=None,
              lport=0, rport=0, when: datetime | None = None,
              owner=True, inetaf=True, laddr=True) -> None:
    off = page * PAGE
    mem[off + 4:off + 8] = tag
    if state is not None:
        struct.pack_into("<I", mem, off + 0x08, state)
    p = off + 0x10
    if inetaf:
        struct.pack_into("<Q", mem, p, va_of(P_INETAF))
    p += 8
    if laddr:
        struct.pack_into("<Q", mem, p, va_of(P_INADDR))
    p += 8
    if owner:
        struct.pack_into("<Q", mem, p, va_of(P_SYSTEM) + 0x10)
    if lport:
        struct.pack_into(">H", mem, off + 0x30, lport)
    if rport:
        struct.pack_into(">H", mem, off + 0x32, rport)
    if when:
        struct.pack_into("<Q", mem, off + 0x40, ft(when))


def build_image() -> bytes:
    mem = bytearray(N_PAGES * PAGE)
    _page_tables(mem)
    _system_object(mem)
    _proc_tag_with_dtb(mem)
    _inetaf(mem)
    _inaddr(mem)
    _endpoint(mem, P_TCPE, b"TcpE", state=4, lport=49213, rport=443,
              when=datetime(2026, 3, 1, 9, 15, 0))
    _endpoint(mem, P_TCPL, b"TcpL", lport=445,
              when=datetime(2026, 3, 1, 8, 0, 0))
    _endpoint(mem, P_UDPA, b"UdpA", lport=138,
              when=datetime(2026, 3, 1, 8, 1, 0), laddr=False)
    return _lime(bytes(mem))


def build_image_no_dtb() -> bytes:
    mem = bytearray(N_PAGES * PAGE)
    _endpoint(mem, P_TCPE, b"TcpE", state=4, lport=49213, rport=443,
              when=datetime(2026, 3, 1, 9, 15, 0), owner=False, inetaf=False,
              laddr=False)
    return _lime(bytes(mem))


_LIME_MAGIC = 0x4C694D45


def _lime(payload: bytes) -> bytes:
    hdr = struct.pack("<IIQQQ", _LIME_MAGIC, 1, 0, len(payload) - 1, 0)
    return hdr + payload
