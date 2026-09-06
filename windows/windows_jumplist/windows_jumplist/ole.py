r"""Minimal reader for the OLE2 / Compound File Binary Format ([MS-CFB]).

Enough to enumerate and extract streams from a
``*.automaticDestinations-ms`` jump list (or any CFBF container).

Header (512 bytes)::

    0x00  8   signature D0 CF 11 E0 A1 B1 1A E1
    0x1e  u16 sector shift          (>> for the FAT, usually 9  -> 512-byte)
    0x20  u16 mini sector shift     (usually 6 -> 64-byte)
    0x2c  u32 number of FAT sectors
    0x30  u32 first directory sector
    0x38  u32 mini-stream cutoff    (usually 4096)
    0x3c  u32 first mini-FAT sector
    0x40  u32 number of mini-FAT sectors
    0x44  u32 first DIFAT sector
    0x48  u32 number of DIFAT sectors
    0x4c  109 x u32  the first 109 FAT-sector locations (DIFAT)

Directory entry (128 bytes): name (64), name length (2), type (1),
colour (1), left / right / child sibling (4 each), CLSID (16), state (4),
created / modified (8 each), starting sector (4), stream size (8).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF

TYPE_ROOT = 5
TYPE_STREAM = 2
TYPE_STORAGE = 1


class OleError(ValueError):
    pass


@dataclass
class DirEntry:
    name: str
    entry_type: int
    start_sector: int
    size: int
    left: int
    right: int
    child: int
    index: int


class OleFile:
    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or data[:8] != SIGNATURE:
            raise OleError("not an OLE2 compound file")
        self.raw = data
        self.sector_size = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self.mini_sector_size = 1 << struct.unpack_from("<H", data, 0x20)[0]
        self.num_fat = struct.unpack_from("<I", data, 0x2C)[0]
        self.first_dir = struct.unpack_from("<I", data, 0x30)[0]
        self.mini_cutoff = struct.unpack_from("<I", data, 0x38)[0]
        self.first_minifat = struct.unpack_from("<I", data, 0x3C)[0]
        self.num_minifat = struct.unpack_from("<I", data, 0x40)[0]
        self.first_difat = struct.unpack_from("<I", data, 0x44)[0]
        self.num_difat = struct.unpack_from("<I", data, 0x48)[0]

        self._fat = self._load_fat()
        self._minifat = self._load_minifat()
        self.entries = self._load_directory()
        self._mini_stream = self._read_chain(
            self.entries[0].start_sector, self.entries[0].size)

    # -- sector access ------------------------------------------
    def _sector(self, n: int) -> bytes:
        start = 512 + n * self.sector_size
        return self.raw[start:start + self.sector_size]

    def _difat(self) -> list[int]:
        entries = list(struct.unpack_from("<109I", self.raw, 0x4C))
        sec = self.first_difat
        guard = 0
        while sec not in (ENDOFCHAIN, FREESECT) and guard < 100000:
            block = self._sector(sec)
            vals = struct.unpack_from(f"<{self.sector_size // 4}I", block, 0)
            entries.extend(vals[:-1])
            sec = vals[-1]
            guard += 1
        return [e for e in entries if e not in (FREESECT,)]

    def _load_fat(self) -> list[int]:
        fat: list[int] = []
        for fs in self._difat():
            if fs in (FREESECT, ENDOFCHAIN):
                continue
            block = self._sector(fs)
            fat.extend(struct.unpack_from(f"<{self.sector_size // 4}I", block, 0))
        return fat

    def _load_minifat(self) -> list[int]:
        if self.first_minifat in (ENDOFCHAIN, FREESECT):
            return []
        data = self._read_chain(self.first_minifat, -1)
        return list(struct.unpack_from(f"<{len(data) // 4}I", data, 0))

    def _read_chain(self, start: int, size: int) -> bytes:
        out = bytearray()
        sec = start
        guard = 0
        while sec not in (ENDOFCHAIN, FREESECT) and guard < 10_000_000:
            out += self._sector(sec)
            if sec >= len(self._fat):
                break
            sec = self._fat[sec]
            guard += 1
        return bytes(out) if size < 0 else bytes(out[:size])

    def _read_mini_chain(self, start: int, size: int) -> bytes:
        out = bytearray()
        sec = start
        guard = 0
        while sec not in (ENDOFCHAIN, FREESECT) and guard < 10_000_000:
            off = sec * self.mini_sector_size
            out += self._mini_stream[off:off + self.mini_sector_size]
            if sec >= len(self._minifat):
                break
            sec = self._minifat[sec]
            guard += 1
        return bytes(out[:size])

    # -- directory ---------------------------------------------
    def _load_directory(self) -> list[DirEntry]:
        raw = self._read_chain(self.first_dir, -1)
        entries: list[DirEntry] = []
        for i in range(0, len(raw), 128):
            e = raw[i:i + 128]
            if len(e) < 128:
                break
            name_len = struct.unpack_from("<H", e, 64)[0]
            etype = e[66]
            if etype == 0:
                entries.append(DirEntry("", 0, 0, 0, NOSTREAM, NOSTREAM,
                                        NOSTREAM, i // 128))
                continue
            name = e[:max(name_len - 2, 0)].decode("utf-16-le", "replace")
            left, right, child = struct.unpack_from("<III", e, 68)
            start, = struct.unpack_from("<I", e, 116)
            size, = struct.unpack_from("<Q", e, 120)
            entries.append(DirEntry(name, etype, start, size, left, right,
                                    child, i // 128))
        return entries

    # -- public API ------------------------------------------
    def list_streams(self) -> list[str]:
        return [e.name for e in self.entries if e.entry_type == TYPE_STREAM]

    def open_stream(self, name: str) -> bytes:
        for e in self.entries:
            if e.entry_type == TYPE_STREAM and e.name == name:
                if e.size < self.mini_cutoff:
                    return self._read_mini_chain(e.start_sector, e.size)
                return self._read_chain(e.start_sector, e.size)
        raise OleError(f"stream not found: {name!r}")
