"""exFAT read-only backend (allocated entries; deleted best-effort)."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

from recovery_fs.engine import Backend, FsEntry

_E_BITMAP = 0x81
_E_UPCASE = 0x82
_E_LABEL = 0x83
_E_FILE = 0x85
_E_STREAM = 0xC0
_E_NAME = 0xC1


def _ts(dw: int, ms10: int = 0, tzoff: int = 0) -> str:
    if dw == 0:
        return ""
    sec = (dw & 0x1F) * 2
    minute = (dw >> 5) & 0x3F
    hour = (dw >> 11) & 0x1F
    day = (dw >> 16) & 0x1F
    month = (dw >> 21) & 0x0F
    year = ((dw >> 25) & 0x7F) + 1980
    try:
        dt = datetime(year, month or 1, day or 1, hour, minute,
                      min(sec, 59), tzinfo=timezone.utc)
        dt += timedelta(milliseconds=ms10 * 10)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ""


class ExfatBackend(Backend):
    fs_name = "exfat"

    def __init__(self, stream, offset: int = 0):
        self._s = stream
        self._base = offset
        bs = self._read(0, 512)
        self.part_off = struct.unpack_from("<Q", bs, 0x40)[0]
        self.vol_len = struct.unpack_from("<Q", bs, 0x48)[0]
        self.fat_off = struct.unpack_from("<I", bs, 0x50)[0]
        self.fat_len = struct.unpack_from("<I", bs, 0x54)[0]
        self.heap_off = struct.unpack_from("<I", bs, 0x58)[0]
        self.cluster_count = struct.unpack_from("<I", bs, 0x5C)[0]
        self.root_cluster = struct.unpack_from("<I", bs, 0x60)[0]
        self.bps = 1 << bs[0x6C]
        self.spc = 1 << bs[0x6D]
        self.cs = self.bps * self.spc
        self._fat = self._read(self.fat_off * self.bps,
                               self.fat_len * self.bps)
        self._bitmap = b""

    def _read(self, off, n):
        self._s.seek(self._base + off)
        return self._s.read(n)

    def _cluster_off(self, cl: int) -> int:
        return (self.heap_off + (cl - 2) * self.spc) * self.bps

    def _fat_next(self, cl: int) -> int:
        if cl * 4 + 4 > len(self._fat):
            return 0xFFFFFFFF
        return struct.unpack_from("<I", self._fat, cl * 4)[0]

    def _read_run(self, start: int, size: int, no_fat_chain: bool) -> bytes:
        out = bytearray()
        if no_fat_chain:
            need = (size + self.cs - 1) // self.cs
            out += self._read(self._cluster_off(start), need * self.cs)
        else:
            cl = start
            seen = set()
            while 2 <= cl < self.cluster_count + 2 and cl not in seen:
                seen.add(cl)
                out += self._read(self._cluster_off(cl), self.cs)
                if len(out) >= size:
                    break
                cl = self._fat_next(cl)
                if cl >= 0xFFFFFFF7:
                    break
        return bytes(out[:size]) if size else bytes(out)

    def _dir_bytes(self, cluster: int) -> bytes:
        return self._read_run(cluster, 0, False)

    def _walk(self, cluster: int, path: str, seen: set, include_deleted):
        raw = self._dir_bytes(cluster)
        i = 0
        while i + 32 <= len(raw):
            etype = raw[i]
            if etype == 0x00:
                break
            in_use = bool(etype & 0x80)
            base = etype & 0x7F
            if base == 0x05 and (in_use or include_deleted):   # FILE entry
                fe = raw[i:i + 32]
                secondary = fe[1]
                attrs = struct.unpack_from("<H", fe, 4)[0]
                is_dir = bool(attrs & 0x10)
                ctime, mtime, atime = struct.unpack_from("<III", fe, 8)
                cms, mms = fe[20], fe[21]
                se = raw[i + 32:i + 64]
                if len(se) < 32 or (se[0] & 0x7F) != 0x40:
                    i += 32
                    continue
                flags = se[1]
                no_fat = bool(flags & 0x02)
                name_len = se[3]
                first_cl = struct.unpack_from("<I", se, 20)[0]
                data_len = struct.unpack_from("<Q", se, 24)[0]
                name = []
                for k in range(2, secondary + 1):
                    ne = raw[i + 32 * k: i + 32 * k + 32]
                    if len(ne) < 32 or (ne[0] & 0x7F) != 0x41:
                        break
                    name.append(ne[2:32].decode("utf-16-le", "replace"))
                nm = "".join(name)[:name_len] or "(unnamed)"
                if not in_use:
                    nm = "_" + nm
                full = f"{path}/{nm}" if path else nm
                ent = FsEntry(
                    path=full, name=nm, is_dir=is_dir,
                    size=0 if is_dir else data_len, allocated=in_use,
                    inode=first_cl, fs="exfat",
                    created=_ts(ctime, cms), modified=_ts(mtime, mms),
                    accessed=_ts(atime))
                ent.extra.update(first_cluster=first_cl, no_fat_chain=no_fat,
                                 data_len=data_len)
                yield ent
                if is_dir and in_use and first_cl >= 2 and \
                        first_cl not in seen:
                    seen.add(first_cl)
                    yield from self._walk(first_cl, full, seen,
                                          include_deleted)
                i += 32 * max(secondary + 1, 1)
                continue
            i += 32

    def entries(self, *, include_deleted=True):
        yield from self._walk(self.root_cluster, "", set(), include_deleted)

    def read(self, entry: FsEntry) -> bytes:
        cl = entry.extra.get("first_cluster", entry.inode)
        if not cl or cl < 2:
            return b""
        return self._read_run(cl, entry.extra.get("data_len", entry.size),
                              entry.extra.get("no_fat_chain", False))
