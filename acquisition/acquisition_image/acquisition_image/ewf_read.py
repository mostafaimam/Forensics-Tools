"""Minimal EWF v1 reader - just enough to verify what we wrote."""

from __future__ import annotations

import re
import struct
import zlib
from pathlib import Path

_SIG = (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00")
_DESC = struct.Struct("<16sQQ40sI")


def _segments(path: Path) -> list[Path]:
    m = re.search(r"\.[ELsel]\w\w$", path.name)
    if not m:
        return [path]
    stem = path.name[: m.start()]
    sibs = [p for p in path.parent.iterdir()
            if p.name.startswith(stem) and re.search(r"\.[ELsel]\w\w$", p.name)]

    def key(p):
        e = p.suffix[1:]
        return tuple((int(c) if c.isdigit() else ord(c.lower())) for c in e[1:])
    return sorted(sibs, key=key) or [path]


class EWFReader:
    def __init__(self, path: str):
        self.path = Path(path)
        self._fh: dict[Path, object] = {}
        self.bytes_per_sector = 512
        self.sectors_per_chunk = 64
        self.sector_count = 0
        self.stored_md5 = ""
        self.stored_sha1 = ""
        self._chunks: list[tuple[Path, int, bool]] = []
        self._parse()
        self.chunk_size = self.sectors_per_chunk * self.bytes_per_sector
        self.size = self.sector_count * self.bytes_per_sector

    def _handle(self, p: Path):
        fh = self._fh.get(p)
        if fh is None:
            fh = self._fh[p] = p.open("rb")
        return fh

    def _parse(self) -> None:
        for seg in _segments(self.path):
            fh = self._handle(seg)
            if fh.read(8) not in _SIG:
                raise ValueError(f"{seg.name}: not EWF")
            fh.read(5)
            offset = 13
            tables = []
            while True:
                fh.seek(offset)
                raw = fh.read(76)
                if len(raw) < 76:
                    break
                stype, nxt, size, _pad, _cs = _DESC.unpack(raw)
                stype = stype.rstrip(b"\x00").decode("ascii", "replace")
                body = offset + 76
                if stype in ("volume", "disk"):
                    self._volume(fh, body)
                elif stype == "table":
                    tables.append((seg, body))
                elif stype == "digest":
                    fh.seek(body)
                    d = fh.read(36)
                    self.stored_md5 = d[:16].hex()
                    self.stored_sha1 = d[16:36].hex()
                elif stype == "hash" and not self.stored_md5:
                    fh.seek(body)
                    self.stored_md5 = fh.read(16).hex()
                if stype in ("next", "done") or nxt <= offset:
                    break
                offset = nxt
            for seg_p, toff in tables:
                self._table(seg_p, toff)

    def _volume(self, fh, body: int) -> None:
        fh.seek(body)
        v = fh.read(1052)
        _mt, _cc, spc, bps, sc = struct.unpack_from("<B3xIIII", v, 0)
        if spc:
            self.sectors_per_chunk = spc
        if bps:
            self.bytes_per_sector = bps
        self.sector_count = sc

    def _table(self, seg: Path, body: int) -> None:
        fh = self._handle(seg)
        fh.seek(body)
        hdr = fh.read(24)
        count = struct.unpack_from("<I", hdr, 0)[0]
        base = struct.unpack_from("<Q", hdr, 8)[0]
        ents = fh.read(4 * count)
        for i in range(count):
            e = struct.unpack_from("<I", ents, i * 4)[0]
            self._chunks.append((seg, base + (e & 0x7FFFFFFF), bool(e & 0x80000000)))

    def chunks(self):
        for i, (seg, off, comp) in enumerate(self._chunks):
            fh = self._handle(seg)
            fh.seek(off)
            if comp:
                slab = fh.read(self.chunk_size * 2 + 4096)
                data = zlib.decompressobj().decompress(slab, self.chunk_size)
            else:
                data = fh.read(self.chunk_size)
            if i == len(self._chunks) - 1:
                remain = self.size - i * self.chunk_size
                data = data[:remain]
            yield data

    def close(self) -> None:
        for fh in self._fh.values():
            fh.close()
