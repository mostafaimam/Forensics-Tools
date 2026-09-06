"""Linux physical-memory acquisition via /proc/kcore + /proc/iomem."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from acquisition_ram import lime

_CHUNK = 8 << 20
# plausible PAGE_OFFSET window (x86-64 and arm64)
_PO_LO = 0xFFFF000000000000
_PO_HI = 0xFFFFFF0000000000


_O_RDONLY = os.O_RDONLY | getattr(os, "O_BINARY", 0)


def _pread(fd: int, n: int, off: int) -> bytes:
    """os.pread where available (Linux), else lseek+read (dev/test on Windows)."""
    if hasattr(os, "pread"):
        return os.pread(fd, n, off)
    os.lseek(fd, off, os.SEEK_SET)
    return os.read(fd, n)


@dataclass
class Segment:
    p_offset: int
    p_vaddr: int
    p_filesz: int


@dataclass
class LinuxProbe:
    kcore: str
    iomem: str
    kcore_readable: bool = False
    ram_ranges: list = field(default_factory=list)   # [(start, end_exclusive)]
    total_ram: int = 0
    page_offset: int = 0
    direct_map: Segment | None = None
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.kcore_readable and bool(self.ram_ranges) and \
            self.direct_map is not None


# -- parsing -----------------------------------------------------
def parse_iomem(text: str) -> list[tuple[int, int]]:
    out = []
    for line in text.splitlines():
        if line[:1] in (" ", "\t"):            # nested child range
            continue
        addr, _, label = line.partition(" : ")
        if label.strip() != "System RAM":
            continue
        lo, _, hi = addr.strip().partition("-")
        try:
            out.append((int(lo, 16), int(hi, 16) + 1))
        except ValueError:
            continue
    out.sort()
    return out


def parse_elf_segments(header_bytes: bytes, read_at) -> list[Segment]:
    if header_bytes[:4] != b"\x7fELF":
        raise ValueError("/proc/kcore is not an ELF file")
    is64 = header_bytes[4] == 2
    le = header_bytes[5] == 1
    end = "<" if le else ">"
    if not is64:
        raise ValueError("only 64-bit /proc/kcore is supported")
    e_phoff = struct.unpack_from(end + "Q", header_bytes, 32)[0]
    e_phentsize = struct.unpack_from(end + "H", header_bytes, 54)[0]
    e_phnum = struct.unpack_from(end + "H", header_bytes, 56)[0]
    ph = read_at(e_phoff, e_phentsize * e_phnum)
    segs = []
    for i in range(e_phnum):
        off = i * e_phentsize
        p_type = struct.unpack_from(end + "I", ph, off)[0]
        if p_type != 1:                        # PT_LOAD
            continue
        p_offset = struct.unpack_from(end + "Q", ph, off + 8)[0]
        p_vaddr = struct.unpack_from(end + "Q", ph, off + 16)[0]
        p_filesz = struct.unpack_from(end + "Q", ph, off + 32)[0]
        segs.append(Segment(p_offset, p_vaddr, p_filesz))
    return segs


def _direct_map(segs: list[Segment]) -> Segment | None:
    cand = [s for s in segs if _PO_LO <= s.p_vaddr < _PO_HI and s.p_filesz]
    if not cand:
        return None
    return max(cand, key=lambda s: s.p_filesz)


# -- probe -----------------------------------------------------
def probe(kcore: str = "/proc/kcore", iomem: str = "/proc/iomem") -> LinuxProbe:
    p = LinuxProbe(kcore=kcore, iomem=iomem)
    try:
        with open(iomem, "r") as fh:
            p.ram_ranges = parse_iomem(fh.read())
        p.total_ram = sum(e - s for s, e in p.ram_ranges)
    except OSError as e:
        p.warnings.append(f"cannot read {iomem}: {e}")

    try:
        fd = os.open(kcore, _O_RDONLY)
    except OSError as e:
        p.warnings.append(f"cannot open {kcore}: {e} (need root?)")
        return p
    try:
        hdr = _pread(fd, 64, 0)
        if not hdr:
            p.warnings.append(f"{kcore} opened but reads empty "
                              "(kernel lockdown / restricted)")
            return p
        p.kcore_readable = True
        segs = parse_elf_segments(hdr, lambda o, n: _pread(fd, n, o))
        dm = _direct_map(segs)
        if dm is None:
            p.warnings.append("no direct-map PT_LOAD segment found in kcore")
        else:
            p.direct_map = dm
            p.page_offset = dm.p_vaddr
    except (ValueError, OSError) as e:
        p.warnings.append(f"parsing {kcore}: {e}")
    finally:
        os.close(fd)
    return p


# -- capture ---------------------------------------------------
def _read_phys(fd: int, dm: Segment, phys: int, length: int) -> bytes:
    """Read *length* bytes of physical RAM starting at *phys* via the physmap."""
    file_off = dm.p_offset + phys
    if phys >= dm.p_filesz:
        return b"\x00" * length
    length = min(length, dm.p_filesz - phys)
    try:
        data = _pread(fd, length, file_off)
    except OSError:
        data = b""
    if len(data) < length:
        data += b"\x00" * (length - len(data))
    return data


def capture(probe_result: LinuxProbe, out_path: str, fmt: str = "lime", *,
            hashers: dict | None = None, progress=None):
    """Write the dump.  Returns (ranges, bytes_written, warnings)."""
    if not probe_result.ok:
        raise RuntimeError("probe failed: " + "; ".join(probe_result.warnings)
                           or "no readable memory source")
    dm = probe_result.direct_map
    ranges = probe_result.ram_ranges
    total = probe_result.total_ram
    hashers = hashers or {}
    warnings = list(probe_result.warnings)
    fd = os.open(probe_result.kcore, _O_RDONLY)
    written = 0
    done = 0
    out_ranges = []
    try:
        with open(out_path, "wb") as of:
            last_end = 0
            for s, e in ranges:
                if fmt == "lime":
                    hdr = lime.header(s, e - 1)
                    of.write(hdr)
                    for h in hashers.values():
                        h.update(hdr)
                    written += len(hdr)
                elif fmt == "padded" and s > last_end:
                    gap = s - last_end
                    of.seek(gap, 1)
                    # explicit zero-fill so the hash is deterministic
                    of.write(b"")            # no-op; sparse hole
                    _hash_zeros(hashers, gap)
                    written += gap
                out_ranges.append({"start": s, "end": e,
                                   "file_offset": of.tell()})
                pos = s
                while pos < e:
                    n = min(_CHUNK, e - pos)
                    data = _read_phys(fd, dm, pos, n)
                    of.write(data)
                    for h in hashers.values():
                        h.update(data)
                    written += n
                    done += n
                    pos += n
                    if progress:
                        progress(done, total)
                last_end = e
    finally:
        os.close(fd)
    return out_ranges, written, warnings


def _hash_zeros(hashers: dict, n: int) -> None:
    block = b"\x00" * min(n, 1 << 20)
    while n > 0:
        take = min(len(block), n)
        for h in hashers.values():
            h.update(block[:take])
        n -= take
