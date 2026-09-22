"""Physical-memory dump loader: raw / LiME / ELF core / Windows crash dump.

Vendored verbatim into the other ``memory_*`` tools.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

_LIME_MAGIC = 0x4C694D45          # "LiME"
_LIME_HDR = struct.Struct("<IIQQQ")
_CHUNK = 8 << 20


class MemoryImageError(Exception):
    pass


@dataclass
class Run:
    """A contiguous physical range backed by *file_offset* in the dump."""
    phys_start: int
    size: int
    file_offset: int

    @property
    def phys_end(self) -> int:
        return self.phys_start + self.size


@dataclass
class ImageInfo:
    fmt: str                       # raw | lime | elf | winkdump | winbmp
    file_size: int
    phys_size: int = 0             # highest physical address + 1
    mapped_size: int = 0           # sum of run sizes
    runs: list = field(default_factory=list)
    os_hints: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


def detect_format(head: bytes, path: Path) -> str:
    if head[:4] == b"\x7fELF" and len(head) >= 18 and \
            struct.unpack_from("<H", head, 16)[0] == 4:      # ET_CORE
        return "elf"
    if len(head) >= 4 and struct.unpack_from("<I", head, 0)[0] == _LIME_MAGIC:
        return "lime"
    if head[:8] == b"PAGEDUMP" or head[:4] == b"PAGE":
        if head[4:8] in (b"DUMP", b"DU64"):
            return "winkdump"
    return "raw"


class MemoryImage:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._fh = self.path.open("rb")
        self._fh.seek(0, 2)
        self.file_size = self._fh.tell()
        self._fh.seek(0)
        head = self._fh.read(0x2100)
        self.fmt = detect_format(head, self.path)
        self.runs: list[Run] = []
        self.os_hints: dict = {}
        self.warnings: list[str] = []
        {"raw": self._load_raw, "lime": self._load_lime,
         "elf": self._load_elf, "winkdump": self._load_winkdump}[self.fmt](head)
        self.runs.sort(key=lambda r: r.phys_start)
        self.phys_size = max((r.phys_end for r in self.runs), default=0)
        self.mapped_size = sum(r.size for r in self.runs)

    # -- format loaders -------------------------------------------
    def _load_raw(self, _head) -> None:
        self.runs = [Run(0, self.file_size, 0)]

    def _load_lime(self, _head) -> None:
        pos = 0
        while pos + _LIME_HDR.size <= self.file_size:
            self._fh.seek(pos)
            raw = self._fh.read(_LIME_HDR.size)
            if len(raw) < _LIME_HDR.size:
                break
            magic, ver, s, e, _res = _LIME_HDR.unpack(raw)
            if magic != _LIME_MAGIC:
                self.warnings.append(f"bad LiME header at {pos:#x}")
                break
            size = e - s + 1
            data_off = pos + _LIME_HDR.size
            self.runs.append(Run(s, size, data_off))
            pos = data_off + size
        if not self.runs:
            raise MemoryImageError("no valid LiME ranges")

    def _load_elf(self, head) -> None:
        le = head[5] == 1
        en = "<" if le else ">"
        e_phoff = struct.unpack_from(en + "Q", head, 32)[0]
        e_phentsize = struct.unpack_from(en + "H", head, 54)[0]
        e_phnum = struct.unpack_from(en + "H", head, 56)[0]
        self._fh.seek(e_phoff)
        ph = self._fh.read(e_phentsize * e_phnum)
        for i in range(e_phnum):
            o = i * e_phentsize
            if struct.unpack_from(en + "I", ph, o)[0] != 1:   # PT_LOAD
                continue
            p_offset = struct.unpack_from(en + "Q", ph, o + 8)[0]
            p_vaddr = struct.unpack_from(en + "Q", ph, o + 16)[0]
            p_paddr = struct.unpack_from(en + "Q", ph, o + 24)[0]
            p_filesz = struct.unpack_from(en + "Q", ph, o + 32)[0]
            phys = p_paddr if p_paddr and p_paddr < (1 << 48) else p_vaddr
            if p_filesz:
                self.runs.append(Run(phys, p_filesz, p_offset))
        if not self.runs:
            raise MemoryImageError("ELF core has no PT_LOAD segments")

    def _load_winkdump(self, head) -> None:
        x64 = head[4:8] == b"DU64"
        self.os_hints["os"] = "windows"
        self.os_hints["arch"] = "x64" if x64 else "x86"
        if x64:
            self.os_hints["directory_table_base"] = \
                struct.unpack_from("<Q", head, 0x28)[0]
            self.os_hints["ps_active_process_head"] = \
                struct.unpack_from("<Q", head, 0x40)[0]
            self.os_hints["ps_loaded_module_list"] = \
                struct.unpack_from("<Q", head, 0x48)[0]
            self.os_hints["number_processors"] = \
                struct.unpack_from("<I", head, 0x38)[0]
            dump_type = struct.unpack_from("<I", head, 0xF98)[0]
            hdr_size = 0x2000
            desc_off = 0x88
        else:
            self.os_hints["directory_table_base"] = \
                struct.unpack_from("<I", head, 0x10)[0]
            dump_type = struct.unpack_from("<I", head, 0xF88)[0]
            hdr_size = 0x1000
            desc_off = 0x64
        self.os_hints["dump_type"] = {1: "full", 2: "kernel", 5: "bitmap-full",
                                      6: "bitmap-kernel"}.get(dump_type,
                                                              str(dump_type))
        # bitmap dumps carry an SDMP/FDMP block after the header
        tag = head[0x2000:0x2004]
        if tag in (b"SDMP", b"FDMP") or dump_type in (5, 6):
            self._load_winbmp(head, x64)
            self.fmt = "winbmp"
            return
        n_runs = struct.unpack_from("<I", head, desc_off)[0]
        entry = desc_off + (16 if x64 else 8)
        file_pos = hdr_size
        for i in range(min(n_runs, 4096)):
            if x64:
                base_page, page_count = struct.unpack_from(
                    "<QQ", head, entry + i * 16)
            else:
                base_page, page_count = struct.unpack_from(
                    "<II", head, entry + i * 8)
            size = page_count * 0x1000
            self.runs.append(Run(base_page * 0x1000, size, file_pos))
            file_pos += size
        if not self.runs:
            raise MemoryImageError("crash dump has no physical memory runs")

    def _load_winbmp(self, head, x64) -> None:
        base = 0x2000
        first_page = struct.unpack_from("<Q", head, base + 0x18)[0]
        total_pages = struct.unpack_from("<Q", head, base + 0x20)[0]
        bitmap_off = base + 0x28
        self._fh.seek(bitmap_off)
        bitmap = self._fh.read((total_pages + 7) // 8)
        file_pos = first_page
        cur_start = None
        cur_count = 0
        for pfn in range(total_pages):
            present = (bitmap[pfn >> 3] >> (pfn & 7)) & 1
            if present:
                if cur_start is None:
                    cur_start = pfn
                cur_count += 1
            elif cur_start is not None:
                self.runs.append(Run(cur_start * 0x1000, cur_count * 0x1000,
                                     file_pos))
                file_pos += cur_count * 0x1000
                cur_start, cur_count = None, 0
        if cur_start is not None:
            self.runs.append(Run(cur_start * 0x1000, cur_count * 0x1000,
                                 file_pos))
        if not self.runs:
            raise MemoryImageError("bitmap dump: no present pages")

    # -- reading -------------------------------------------------
    def read_physical(self, addr: int, size: int) -> bytes:
        out = bytearray()
        want_end = addr + size
        pos = addr
        for run in self.runs:
            if pos >= want_end:
                break
            if run.phys_end <= pos or run.phys_start >= want_end:
                continue
            if run.phys_start > pos:                    # gap before this run
                gap = min(run.phys_start, want_end) - pos
                out += b"\x00" * gap
                pos += gap
            local = pos - run.phys_start
            take = min(want_end - pos, run.size - local)
            self._fh.seek(run.file_offset + local)
            chunk = self._fh.read(take)
            out += chunk.ljust(take, b"\x00")
            pos += take
        if pos < want_end:
            out += b"\x00" * (want_end - pos)
        return bytes(out)

    def stream_runs(self, chunk: int = _CHUNK):
        for run in self.runs:
            pos = 0
            while pos < run.size:
                n = min(chunk, run.size - pos)
                self._fh.seek(run.file_offset + pos)
                yield run.phys_start + pos, self._fh.read(n).ljust(n, b"\x00")
                pos += n

    # -- os hints -----------------------------------------------
    def scan_os_hints(self, limit: int = 512 << 20) -> dict:
        if self.os_hints.get("os"):
            return self.os_hints
        scanned = 0
        lin = re.compile(rb"Linux version (\d+\.\d+\.\d+\S*) \(([^)]*)\) "
                         rb"\(([^)]*)\)")
        for _phys, block in self.stream_runs():
            m = lin.search(block)
            if m:
                self.os_hints.update(
                    os="linux", kernel=m.group(1).decode("latin-1"),
                    kernel_builder=m.group(2).decode("latin-1", "replace"))
                break
            if b"\x00\x00\x00\x00\x00Windows" in block or \
                    b"Windows Kernel" in block:
                self.os_hints["os"] = "windows"
                break
            scanned += len(block)
            if scanned > limit:
                self.warnings.append("OS hint scan stopped at limit")
                break
        return self.os_hints

    def info(self) -> ImageInfo:
        return ImageInfo(
            fmt=self.fmt, file_size=self.file_size, phys_size=self.phys_size,
            mapped_size=self.mapped_size,
            runs=[{"phys_start": r.phys_start, "size": r.size,
                   "file_offset": r.file_offset} for r in self.runs],
            os_hints=dict(self.os_hints), warnings=list(self.warnings))

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
