"""Synthetic /proc/kcore (ELF64) + /proc/iomem and a fake OS root."""

from __future__ import annotations

import struct
from pathlib import Path

PAGE_OFFSET = 0xFFFF888000000000
DATA_START = 0x1000            # where "physical address 0" sits in the file


def make_kcore(phys_ram: bytes, *, page_offset: int = PAGE_OFFSET) -> bytes:
    """An ELF64 core whose single PT_LOAD direct-maps *phys_ram* from paddr 0."""
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2                # ELFCLASS64
    ehdr[5] = 1                # little-endian
    ehdr[6] = 1
    struct.pack_into("<H", ehdr, 16, 4)        # e_type = ET_CORE
    struct.pack_into("<H", ehdr, 18, 0x3E)     # e_machine = x86-64
    struct.pack_into("<I", ehdr, 20, 1)
    struct.pack_into("<Q", ehdr, 32, 64)       # e_phoff
    struct.pack_into("<H", ehdr, 52, 64)       # e_ehsize
    struct.pack_into("<H", ehdr, 54, 56)       # e_phentsize
    struct.pack_into("<H", ehdr, 56, 1)        # e_phnum

    ph = bytearray(56)
    struct.pack_into("<I", ph, 0, 1)                       # PT_LOAD
    struct.pack_into("<I", ph, 4, 7)                       # RWX
    struct.pack_into("<Q", ph, 8, DATA_START)              # p_offset
    struct.pack_into("<Q", ph, 16, page_offset)            # p_vaddr
    struct.pack_into("<Q", ph, 24, 0)                      # p_paddr
    struct.pack_into("<Q", ph, 32, len(phys_ram))          # p_filesz
    struct.pack_into("<Q", ph, 40, len(phys_ram))          # p_memsz

    out = bytearray(DATA_START)
    out[0:64] = ehdr
    out[64:64 + 56] = ph
    out += phys_ram
    return bytes(out)


def make_iomem(ranges: list[tuple[int, int]]) -> str:
    """*ranges* are (start, end_exclusive)."""
    lines = ["00000000-00000fff : Reserved"]
    for s, e in ranges:
        lines.append(f"{s:08x}-{e - 1:08x} : System RAM")
        lines.append(f"  {s + 16:08x}-{s + 32:08x} : Kernel code")   # child
    lines.append("fee00000-fee00fff : Local APIC")
    return "\n".join(lines) + "\n"


def phys_ram(size: int = 0x40000) -> bytes:
    return bytes((i * 7 + (i >> 8)) % 256 for i in range(size))


def windows_root(base: Path) -> Path:
    root = base / "cdrive"
    (root / "Windows" / "System32").mkdir(parents=True)
    (root / "Windows" / "Minidump").mkdir(parents=True)
    (root / "pagefile.sys").write_bytes(b"PAGE" * 4096)
    (root / "hiberfil.sys").write_bytes(b"HIBR" * 8192)
    (root / "swapfile.sys").write_bytes(b"SWAP" * 256)
    (root / "Windows" / "MEMORY.DMP").write_bytes(b"PMDM" * 1024)
    (root / "Windows" / "Minidump" / "010124-1234-01.dmp").write_bytes(b"MDMP" * 64)
    return root


def macos_root(base: Path) -> Path:
    root = base / "macroot"
    (root / "private" / "var" / "vm").mkdir(parents=True)
    (root / "cores").mkdir(parents=True)
    (root / "private" / "var" / "vm" / "sleepimage").write_bytes(b"SLEEP" * 4096)
    (root / "private" / "var" / "vm" / "swapfile0").write_bytes(b"SWP0" * 512)
    (root / "private" / "var" / "vm" / "swapfile1").write_bytes(b"SWP1" * 512)
    return root
