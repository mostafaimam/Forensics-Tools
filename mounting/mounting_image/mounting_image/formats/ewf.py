"""EWF (Expert Witness Format, ``.E01``) - read-only.

Supports EWF version 1 (``EVF`` signature): the common v1 layout with
zlib-compressed or stored 32 KiB / 64 KiB chunks, single or multi segment.
"""

from __future__ import annotations

import re
import struct
import zlib
from pathlib import Path

from mounting_image.formats.base import Image, ImageError

_SIG_V1 = b"EVF\x09\x0d\x0a\xff\x00"
_SIG_L01 = b"LVF\x09\x0d\x0a\xff\x00"

_DESC = struct.Struct("<16sQQ40sI")           # type, next, size, pad, checksum


def _seg_sort_key(name: str):
    m = re.search(r"\.([ELes])(\w\w)$", name)
    if not m:
        return (0,)
    a, b = m.group(2)
    def v(c): return int(c) if c.isdigit() else ord(c.lower()) - ord("a") + 10
    return (v(a) * 36 + v(b),)


class EWFImage(Image):
    format_name = "ewf"

    def __init__(self, path: str | Path):
        path = Path(path)
        self._segments = self._resolve(path)
        self._fh: dict[Path, object] = {}
        self.metadata: dict[str, str] = {}
        self.bytes_per_sector = 512
        self.sectors_per_chunk = 64
        self._sector_count = 0
        self._chunk_count = 0
        self._chunks: list[tuple[Path, int, bool]] = []   # (seg, file_off, compressed)
        self._parse()
        self.chunk_size = self.sectors_per_chunk * self.bytes_per_sector
        self.sector_size = self.bytes_per_sector
        self._size = self._sector_count * self.bytes_per_sector
        if not self._size and self._chunks:
            self._size = len(self._chunks) * self.chunk_size
        self._cache: tuple[int, bytes] | None = None

    # -- segment discovery ---------------------------------------------
    def _resolve(self, path: Path) -> list[Path]:
        m = re.search(r"\.([ELes])\w\w$", path.name)
        if not m:
            return [path]
        stem = path.name[: m.start()]
        sibs = [p for p in path.parent.iterdir()
                if p.name.startswith(stem)
                and re.search(r"\.([ELes])\w\w$", p.name)]
        sibs.sort(key=lambda p: _seg_sort_key(p.name))
        return sibs or [path]

    def _handle(self, p: Path):
        fh = self._fh.get(p)
        if fh is None:
            fh = self._fh[p] = p.open("rb")
        return fh

    # -- structural parse -------------------------------------------
    def _parse(self) -> None:
        for seg in self._segments:
            fh = self._handle(seg)
            sig = fh.read(8)
            if sig not in (_SIG_V1, _SIG_L01):
                raise ImageError(f"{seg.name}: not an EWF v1 segment")
            fh.read(5)                       # 0x01 + segment no (2) + 0x0000
            offset = 13
            table_base_pending = []
            while True:
                fh.seek(offset)
                raw = fh.read(76)
                if len(raw) < 76:
                    break
                stype, nxt, size, _pad, _cs = _DESC.unpack(raw)
                stype = stype.rstrip(b"\x00").decode("ascii", "replace")
                body_off = offset + 76
                if stype in ("header", "header2", "xheader"):
                    self._read_header(fh, body_off, size - 76)
                elif stype in ("volume", "disk"):
                    self._read_volume(fh, body_off, size - 76)
                elif stype in ("table",):
                    table_base_pending.append((seg, body_off, size - 76))
                elif stype == "sectors":
                    pass
                if stype in ("next", "done") or nxt == offset or nxt == 0:
                    break
                offset = nxt
            for seg_p, toff, tlen in table_base_pending:
                self._read_table(seg_p, toff, tlen)

    def _read_header(self, fh, off: int, length: int) -> None:
        fh.seek(off)
        try:
            raw = zlib.decompress(fh.read(length))
        except zlib.error:
            return
        # "header2" is UTF-16 (LE or BE, BOM-prefixed); the older "header"
        # section is Latin-1 / ASCII.
        if raw[:2] == b"\xff\xfe":
            txt = raw[2:].decode("utf-16-le", "replace")
        elif raw[:2] == b"\xfe\xff":
            txt = raw[2:].decode("utf-16-be", "replace")
        else:
            txt = raw.decode("latin-1", "replace")
        lines = txt.replace("\r\n", "\n").splitlines()
        # header: tab-separated "count\ncategory\nkeys\nvalues"
        for i in range(len(lines) - 1):
            keys = lines[i].split("\t")
            vals = lines[i + 1].split("\t")
            if len(keys) > 1 and len(keys) == len(vals):
                names = {"a": "description", "c": "case_number", "n": "evidence_number",
                         "e": "examiner", "t": "notes", "m": "acquired",
                         "u": "system_time", "av": "acquire_version",
                         "ov": "os_version", "p": "password_hash"}
                for k, v in zip(keys, vals):
                    if v:
                        self.metadata.setdefault(names.get(k, k), v)
                break

    def _read_volume(self, fh, off: int, length: int) -> None:
        fh.seek(off)
        v = fh.read(min(length, 1052))
        if len(v) < 20:
            return
        (_mtype, chunk_count, spc, bps, sc) = struct.unpack_from("<B3xIIII", v, 0)
        if 0 < spc <= 1 << 20:
            self.sectors_per_chunk = spc
        if bps in (512, 1024, 2048, 4096):
            self.bytes_per_sector = bps
        self._chunk_count = chunk_count
        self._sector_count = sc

    def _read_table(self, seg: Path, off: int, length: int) -> None:
        fh = self._handle(seg)
        fh.seek(off)
        hdr = fh.read(24)
        if len(hdr) < 24:
            return
        count = struct.unpack_from("<I", hdr, 0)[0]
        base = struct.unpack_from("<Q", hdr, 8)[0]
        entries = fh.read(4 * count)
        for i in range(count):
            ent = struct.unpack_from("<I", entries, i * 4)[0]
            compressed = bool(ent & 0x80000000)
            file_off = base + (ent & 0x7FFFFFFF)
            self._chunks.append((seg, file_off, compressed))

    # -- reading --------------------------------------------------
    @property
    def size(self) -> int:
        return self._size

    def _chunk_bytes(self, index: int) -> bytes:
        if self._cache and self._cache[0] == index:
            return self._cache[1]
        seg, file_off, compressed = self._chunks[index]
        fh = self._handle(seg)
        fh.seek(file_off)
        if compressed:
            slab = fh.read(self.chunk_size * 2 + 4096)
            try:
                data = zlib.decompressobj().decompress(slab, self.chunk_size)
            except zlib.error as e:
                raise ImageError(f"chunk {index}: {e}") from None
        else:
            data = fh.read(self.chunk_size)
        if len(data) < self.chunk_size and index < len(self._chunks) - 1:
            data = data.ljust(self.chunk_size, b"\x00")
        self._cache = (index, data)
        return data

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ImageError("negative offset")
        if not self._chunks or self.chunk_size <= 0:
            raise ImageError("EWF has no chunk table")
        out = bytearray()
        pos = offset
        end = min(offset + length, self._size)
        while pos < end:
            ci = pos // self.chunk_size
            if ci >= len(self._chunks):
                break
            within = pos % self.chunk_size
            chunk = self._chunk_bytes(ci)
            take = min(end - pos, self.chunk_size - within)
            out += chunk[within:within + take]
            pos += take
        if len(out) < length and offset + length <= self._size:
            out += b"\x00" * (length - len(out))
        return bytes(out)

    def close(self) -> None:
        for fh in self._fh.values():
            fh.close()
        self._fh.clear()
