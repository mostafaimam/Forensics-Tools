"""FAT12 / FAT16 / FAT32 read-only backend (allocated + deleted entries)."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from recovery_fs.engine import Backend, FsEntry

_ATTR_DIR = 0x10
_ATTR_VOLID = 0x08
_ATTR_LFN = 0x0F


def _dos_dt(date: int, time: int, tenths: int = 0) -> str:
    if date == 0:
        return ""
    y = ((date >> 9) & 0x7F) + 1980
    mo = (date >> 5) & 0x0F
    d = date & 0x1F
    hh = (time >> 11) & 0x1F
    mm = (time >> 5) & 0x3F
    ss = (time & 0x1F) * 2 + tenths // 100
    try:
        return datetime(y, mo or 1, d or 1, hh, mm, min(ss, 59),
                        tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ""


def _lfn_part(entry: bytes) -> str:
    chars = entry[1:11] + entry[14:26] + entry[28:32]
    out = []
    for i in range(0, len(chars), 2):
        c = chars[i] | (chars[i + 1] << 8)
        if c in (0x0000, 0xFFFF):
            break
        out.append(chr(c))
    return "".join(out)


class FatBackend(Backend):
    fs_name = "fat"

    def __init__(self, stream, offset: int = 0):
        self._s = stream
        self._base = offset
        bs = self._read(0, 512)
        self.bps = struct.unpack_from("<H", bs, 0x0B)[0]
        self.spc = bs[0x0D]
        self.rsvd = struct.unpack_from("<H", bs, 0x0E)[0]
        self.nfats = bs[0x10]
        root_ents = struct.unpack_from("<H", bs, 0x11)[0]
        total16 = struct.unpack_from("<H", bs, 0x13)[0]
        self.fatsz16 = struct.unpack_from("<H", bs, 0x16)[0]
        total32 = struct.unpack_from("<I", bs, 0x20)[0]
        fatsz32 = struct.unpack_from("<I", bs, 0x24)[0]
        self.fatsz = self.fatsz16 or fatsz32
        self.total = total16 or total32
        self.root_ents = root_ents
        self.root_dir_sectors = (root_ents * 32 + self.bps - 1) // self.bps
        self.first_data_sector = (self.rsvd + self.nfats * self.fatsz
                                  + self.root_dir_sectors)
        data_sectors = self.total - self.first_data_sector
        self.clusters = data_sectors // self.spc if self.spc else 0
        if self.fatsz16 and root_ents:
            self.type = "fat12" if self.clusters < 4085 else "fat16"
        else:
            self.type = "fat32"
        self.root_cluster = struct.unpack_from("<I", bs, 0x2C)[0] \
            if self.type == "fat32" else 0
        self._fat = self._read(self.rsvd * self.bps, self.fatsz * self.bps)

    def _read(self, off, n):
        self._s.seek(self._base + off)
        return self._s.read(n)

    def _fat_entry(self, cl: int) -> int:
        if self.type == "fat12":
            p = cl + cl // 2
            v = struct.unpack_from("<H", self._fat, p)[0]
            return (v >> 4) if cl & 1 else (v & 0x0FFF)
        if self.type == "fat16":
            return struct.unpack_from("<H", self._fat, cl * 2)[0]
        return struct.unpack_from("<I", self._fat, cl * 4)[0] & 0x0FFFFFFF

    def _eoc(self, v: int) -> bool:
        return {"fat12": v >= 0xFF8, "fat16": v >= 0xFFF8,
                "fat32": v >= 0x0FFFFFF8}[self.type]

    def _cluster_offset(self, cl: int) -> int:
        return (self.first_data_sector + (cl - 2) * self.spc) * self.bps

    def _chain(self, start: int, max_bytes: int) -> bytes:
        out = bytearray()
        cl = start
        seen = set()
        cs = self.spc * self.bps
        while 2 <= cl < self.clusters + 2 and cl not in seen:
            seen.add(cl)
            out += self._read(self._cluster_offset(cl), cs)
            if len(out) >= max_bytes and max_bytes:
                break
            v = self._fat_entry(cl)
            if self._eoc(v) or v in (0, 1):
                break
            cl = v
        return bytes(out[:max_bytes]) if max_bytes else bytes(out)

    def _read_dir_area(self, cluster: int) -> bytes:
        if cluster == 0:                       # fixed root (12/16)
            off = (self.rsvd + self.nfats * self.fatsz) * self.bps
            return self._read(off, self.root_dir_sectors * self.bps)
        return self._chain(cluster, 0)

    def _walk_dir(self, cluster: int, path: str, seen_clusters: set,
                  include_deleted: bool):
        raw = self._read_dir_area(cluster)
        lfn = []
        for i in range(0, len(raw), 32):
            e = raw[i:i + 32]
            if len(e) < 32 or e[0] == 0x00:
                break
            attr = e[0x0B]
            if attr == _ATTR_LFN and e[0] != 0xE5:
                lfn.insert(0, _lfn_part(e))
                continue
            if e[0] == 0x2E:                    # '.' / '..' self/parent link
                lfn = []
                continue
            deleted = e[0] == 0xE5
            if deleted and not include_deleted:
                lfn = []
                continue
            if attr & _ATTR_VOLID and not (attr & _ATTR_DIR):
                lfn = []
                continue
            short = (e[0:8].decode("latin-1", "replace").rstrip()
                     + ("." + e[8:11].decode("latin-1", "replace").rstrip()
                        if e[8:11].strip() else "")).rstrip(".")
            if deleted:
                short = "_" + short[1:] if short else "_"
            name = "".join(lfn).strip("\x00") if lfn and not deleted else short
            lfn = []
            if name in (".", ".."):
                continue
            is_dir = bool(attr & _ATTR_DIR)
            size = struct.unpack_from("<I", e, 0x1C)[0]
            hi = struct.unpack_from("<H", e, 0x14)[0]
            lo = struct.unpack_from("<H", e, 0x1A)[0]
            first = (hi << 16) | lo
            ctime = struct.unpack_from("<H", e, 0x0E)[0]
            cdate = struct.unpack_from("<H", e, 0x10)[0]
            adate = struct.unpack_from("<H", e, 0x12)[0]
            mtime = struct.unpack_from("<H", e, 0x16)[0]
            mdate = struct.unpack_from("<H", e, 0x18)[0]
            full = f"{path}/{name}" if path else name
            ent = FsEntry(
                path=full, name=name, is_dir=is_dir,
                size=0 if is_dir else size, allocated=not deleted,
                inode=first, fs=self.type,
                created=_dos_dt(cdate, ctime, e[0x0D]),
                modified=_dos_dt(mdate, mtime),
                accessed=_dos_dt(adate, 0))
            ent.extra["first_cluster"] = first
            yield ent
            if is_dir and not deleted and first >= 2 and \
                    first not in seen_clusters:
                seen_clusters.add(first)
                yield from self._walk_dir(first, full, seen_clusters,
                                          include_deleted)

    def entries(self, *, include_deleted=True):
        seen = set()
        start = self.root_cluster if self.type == "fat32" else 0
        yield from self._walk_dir(start, "", seen, include_deleted)

    def read(self, entry: FsEntry) -> bytes:
        cl = entry.extra.get("first_cluster", entry.inode)
        if not cl or cl < 2:
            return b""
        return self._chain(cl, entry.size)
