"""VMware VMDK - monolithic/split sparse and flat extents, read-only.

Stream-optimized (compressed) VMDKs are detected and rejected with a clear
message rather than mis-read.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from mounting_image.formats.base import Image, ImageError

_SPARSE_MAGIC = b"KDMV"
_COWD_MAGIC = b"COWD"
_SECTOR = 512
_FLAG_COMPRESSED = 1 << 16
_EXTENT_RE = re.compile(
    r'^(RW|RDONLY|NOACCESS)\s+(\d+)\s+(FLAT|SPARSE|ZERO|VMFS|VMFSSPARSE)'
    r'(?:\s+"([^"]+)")?(?:\s+(\d+))?', re.IGNORECASE)


class _FlatExtent:
    def __init__(self, path: Path, offset: int, size: int):
        self._fh = path.open("rb")
        self._off = offset
        self.size = size

    def read(self, local: int, length: int) -> bytes:
        self._fh.seek(self._off + local)
        return self._fh.read(length).ljust(length, b"\x00")

    def close(self):
        self._fh.close()


class _ZeroExtent:
    def __init__(self, size: int):
        self.size = size

    def read(self, local: int, length: int) -> bytes:
        return b"\x00" * length

    def close(self):
        pass


class _SparseExtent:
    def __init__(self, path: Path):
        self._fh = path.open("rb")
        h = self._fh.read(512)
        if h[:4] not in (_SPARSE_MAGIC, _COWD_MAGIC):
            raise ImageError(f"{path.name}: not a sparse VMDK extent")
        (magic, _ver, flags, capacity, grain, desc_off, _desc_sz,
         gtes_per_gt) = struct.unpack_from("<4sIIQQQQI", h, 0)
        gd_offset = struct.unpack_from("<Q", h, 56)[0]
        if flags & _FLAG_COMPRESSED:
            raise ImageError(f"{path.name}: stream-optimized (compressed) "
                             "VMDK is not supported yet")
        self.size = capacity * _SECTOR
        self._grain_bytes = grain * _SECTOR
        self._gtes = gtes_per_gt
        self._grain = grain
        n_gt = (capacity + grain * gtes_per_gt - 1) // (grain * gtes_per_gt)
        self._fh.seek(gd_offset * _SECTOR)
        self._gd = list(struct.unpack(f"<{n_gt}I", self._fh.read(4 * n_gt)
                                      .ljust(4 * n_gt, b"\x00")))
        self._gt_cache: dict[int, list] = {}

    def _gt(self, gt_no: int):
        cached = self._gt_cache.get(gt_no)
        if cached is None:
            gd_sec = self._gd[gt_no] if gt_no < len(self._gd) else 0
            if not gd_sec:
                cached = [0] * self._gtes
            else:
                self._fh.seek(gd_sec * _SECTOR)
                cached = list(struct.unpack(
                    f"<{self._gtes}I",
                    self._fh.read(4 * self._gtes).ljust(4 * self._gtes, b"\x00")))
            self._gt_cache[gt_no] = cached
        return cached

    def read(self, local: int, length: int) -> bytes:
        out = bytearray()
        pos = local
        end = min(local + length, self.size)
        while pos < end:
            grain_no = pos // self._grain_bytes
            within = pos % self._grain_bytes
            take = min(end - pos, self._grain_bytes - within)
            gt_no, gt_ent = divmod(grain_no, self._gtes)
            grain_sec = self._gt(gt_no)[gt_ent] if gt_ent < self._gtes else 0
            if not grain_sec:
                out += b"\x00" * take
            else:
                self._fh.seek(grain_sec * _SECTOR + within)
                out += self._fh.read(take).ljust(take, b"\x00")
            pos += take
        return bytes(out).ljust(length, b"\x00") if pos >= end else bytes(out)

    def close(self):
        self._fh.close()


class VMDKImage(Image):
    format_name = "vmdk"

    def __init__(self, path: str | Path):
        path = Path(path)
        head = path.open("rb").read(4)
        self._extents: list[tuple[int, object]] = []
        if head in (_SPARSE_MAGIC, _COWD_MAGIC):
            ext = _SparseExtent(path)
            self._extents.append((0, ext))
            self._size = ext.size
            self.subtype = "monolithicSparse"
        else:
            self._from_descriptor(path)
        pos = 0
        rebuilt = []
        for _, ext in self._extents:
            rebuilt.append((pos, ext))
            pos += ext.size
        self._extents = rebuilt
        self._size = pos

    def _from_descriptor(self, path: Path) -> None:
        try:
            text = path.read_text("latin-1")
        except OSError as e:
            raise ImageError(str(e)) from None
        if "# Disk DescriptorFile" not in text and "createType" not in text:
            raise ImageError("not a VMDK sparse extent or descriptor file")
        m = re.search(r'createType="?([A-Za-z0-9]+)"?', text)
        self.subtype = m.group(1) if m else "unknown"
        for line in text.splitlines():
            em = _EXTENT_RE.match(line.strip())
            if not em:
                continue
            _access, sectors, etype, fname, foff = em.groups()
            size = int(sectors) * _SECTOR
            etype = etype.upper()
            if etype == "ZERO" or not fname:
                self._extents.append((0, _ZeroExtent(size)))
                continue
            target = (path.parent / fname)
            if not target.exists():
                raise ImageError(f"extent file not found: {fname}")
            if etype == "FLAT" or etype == "VMFS":
                self._extents.append(
                    (0, _FlatExtent(target, int(foff or 0) * _SECTOR, size)))
            else:
                self._extents.append((0, _SparseExtent(target)))
        if not self._extents:
            raise ImageError("descriptor lists no usable extents")

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ImageError("negative offset")
        out = bytearray()
        end = min(offset + length, self._size)
        pos = offset
        for start, ext in self._extents:
            if pos >= end:
                break
            if pos >= start + ext.size or end <= start:
                continue
            local = pos - start
            take = min(end - pos, ext.size - local)
            out += ext.read(local, take)
            pos += take
        if len(out) < length and offset + length <= self._size:
            out += b"\x00" * (length - len(out))
        return bytes(out)

    def close(self) -> None:
        for _, ext in self._extents:
            ext.close()
