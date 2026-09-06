"""Synthetic memory dumps in each supported format."""

from __future__ import annotations

import struct

_LIME = struct.Struct("<IIQQQ")


def phys(size: int, seed: int = 0) -> bytes:
    return bytes((i * 13 + seed) % 256 for i in range(size))


def raw_dump(size: int = 0x40000) -> bytes:
    return phys(size)


def lime_dump(ranges) -> tuple[bytes, dict]:
    """ranges: [(start, size)] -> (bytes, {start: data})."""
    out = bytearray()
    data = {}
    for i, (s, size) in enumerate(ranges):
        d = phys(size, seed=i + 1)
        data[s] = d
        out += _LIME.pack(0x4C694D45, 1, s, s + size - 1, 0)
        out += d
    return bytes(out), data


def elf_core(ranges) -> tuple[bytes, dict]:
    """ranges: [(paddr, size)]."""
    n = len(ranges)
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2
    ehdr[5] = 1
    struct.pack_into("<H", ehdr, 16, 4)          # ET_CORE
    struct.pack_into("<Q", ehdr, 32, 64)         # e_phoff
    struct.pack_into("<H", ehdr, 54, 56)         # e_phentsize
    struct.pack_into("<H", ehdr, 56, n)          # e_phnum
    phoff = 64 + 56 * n
    body = bytearray()
    phs = bytearray()
    data = {}
    cur = phoff
    for i, (paddr, size) in enumerate(ranges):
        d = phys(size, seed=i + 5)
        data[paddr] = d
        ph = bytearray(56)
        struct.pack_into("<I", ph, 0, 1)                 # PT_LOAD
        struct.pack_into("<Q", ph, 8, cur)               # p_offset
        struct.pack_into("<Q", ph, 16, 0xffff800000000000 + paddr)  # p_vaddr
        struct.pack_into("<Q", ph, 24, paddr)            # p_paddr
        struct.pack_into("<Q", ph, 32, size)             # p_filesz
        struct.pack_into("<Q", ph, 40, size)
        phs += ph
        body += d
        cur += size
    return bytes(ehdr) + bytes(phs) + bytes(body), data


def winkdump(ranges, *, dtb=0x1aa000, ps_head=0xfffff80012345678) -> tuple[bytes, dict]:
    """A 64-bit full crash dump.  ranges: [(base_page, page_count)]."""
    head = bytearray(0x2000)
    head[0:4] = b"PAGE"
    head[4:8] = b"DU64"
    struct.pack_into("<Q", head, 0x28, dtb)
    struct.pack_into("<I", head, 0x38, 4)                 # NumberProcessors
    struct.pack_into("<Q", head, 0x40, ps_head)
    struct.pack_into("<I", head, 0xF98, 1)                # DumpType = full
    struct.pack_into("<I", head, 0x88, len(ranges))       # NumberOfRuns
    entry = 0x88 + 16
    data = {}
    body = bytearray()
    for i, (base_page, count) in enumerate(ranges):
        struct.pack_into("<QQ", head, entry + i * 16, base_page, count)
        d = phys(count * 0x1000, seed=i + 9)
        data[base_page * 0x1000] = d
        body += d
    return bytes(head) + bytes(body), data
