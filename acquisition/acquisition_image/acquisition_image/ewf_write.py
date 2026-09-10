"""Streaming EWF (Expert Witness Format, ``.E01``) writer - EWF version 1."""

from __future__ import annotations

import struct
import time
import zlib
from pathlib import Path

_SIG = b"EVF\x09\x0d\x0a\xff\x00"
_DESC = struct.Struct("<16sQQ40sI")
_COMPRESSION = {"none": 0, "fast": 1, "best": 9}


def _segment_name(base: Path, n: int) -> Path:
    # disk.E01, disk.E02 ... disk.E99, disk.EAA ...
    stem = base.name
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    if n <= 99:
        ext = f"E{n:02d}"
    else:
        n -= 100
        ext = "E" + chr(ord("A") + n // 26) + chr(ord("A") + n % 26)
    return base.parent / f"{stem}.{ext}"


class EWFWriter:
    def __init__(self, base_path: str, media_size: int, *,
                 sectors_per_chunk: int = 64, bytes_per_sector: int = 512,
                 compression: str = "fast", segment_size: int | None = None,
                 metadata: dict | None = None):
        self.base = Path(base_path)
        self.media_size = media_size
        self.spc = sectors_per_chunk
        self.bps = bytes_per_sector
        self.chunk_size = sectors_per_chunk * bytes_per_sector
        self.level = _COMPRESSION.get(compression, 1)
        self.segment_size = segment_size or (1 << 62)
        self.meta = metadata or {}
        self.total_chunks = (media_size + self.chunk_size - 1) // self.chunk_size

        self._buf = bytearray()
        self._written = 0
        self._chunk_index = 0
        self._seg_no = 0
        self._fh = None
        self._seg_path = None
        self._table: list[tuple[int, bool]] = []   # (abs offset, compressed)
        self._table_base = 0
        self.segments: list[str] = []
        self._open_segment()

    # -- segment lifecycle ------------------------------------------
    def _open_segment(self) -> None:
        self._seg_no += 1
        self._seg_path = _segment_name(self.base, self._seg_no)
        self._fh = self._seg_path.open("wb")
        self.segments.append(str(self._seg_path))
        self._fh.write(_SIG + b"\x01" + struct.pack("<H", self._seg_no) + b"\x00\x00")
        if self._seg_no == 1:
            self._write_section("header2", self._header2())
            self._write_section("header", self._header())
            self._write_section("volume", self._volume())
        # start a sectors section - its data is appended chunk by chunk
        self._sectors_desc_pos = self._fh.tell()
        self._fh.write(b"\x00" * 76)          # placeholder, patched at flush
        self._sectors_data_start = self._fh.tell()
        self._table = []
        self._table_base = self._sectors_data_start

    def _rotate_segment(self) -> None:
        self._close_sectors_and_tables(last=False)
        self._write_section("next", b"", self_ref=True)
        self._fh.close()
        self._open_segment()

    # -- chunk writing -------------------------------------------
    def write(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= self.chunk_size:
            self._emit_chunk(bytes(self._buf[:self.chunk_size]))
            del self._buf[:self.chunk_size]

    def _emit_chunk(self, chunk: bytes) -> None:
        if self.level == 0:
            payload = chunk + struct.pack("<I", zlib.adler32(chunk))
            compressed = False
        else:
            comp = zlib.compress(chunk, self.level)
            if len(comp) < len(chunk):
                payload, compressed = comp, True
            else:
                payload = chunk + struct.pack("<I", zlib.adler32(chunk))
                compressed = False
        pos = self._fh.tell()
        # keep 31-bit table offsets valid
        if pos - self._table_base > 0x7FFFF000:
            self._close_sectors_and_tables(last=False)
            self._sectors_desc_pos = self._fh.tell()
            self._fh.write(b"\x00" * 76)
            self._sectors_data_start = self._fh.tell()
            self._table = []
            self._table_base = self._sectors_data_start
            pos = self._fh.tell()
        self._fh.write(payload)
        self._table.append((pos - self._table_base, compressed))
        self._chunk_index += 1
        self._written += len(chunk)
        if self._fh.tell() >= self.segment_size and \
                self._chunk_index < self.total_chunks:
            self._rotate_segment()

    def _close_sectors_and_tables(self, last: bool) -> None:
        end = self._fh.tell()
        size = 76 + (end - self._sectors_data_start)
        nxt = end
        self._patch_desc(self._sectors_desc_pos, b"sectors", nxt, size)
        # table
        entries = b"".join(
            struct.pack("<I", off | (0x80000000 if comp else 0))
            for off, comp in self._table)
        thdr = bytearray(24)
        struct.pack_into("<I", thdr, 0, len(self._table))
        struct.pack_into("<Q", thdr, 8, self._table_base)
        struct.pack_into("<I", thdr, 20, zlib.adler32(bytes(thdr[:20])))
        tbody = bytes(thdr) + entries + struct.pack("<I", zlib.adler32(entries))
        self._write_section("table", tbody)
        self._write_section("table2", tbody)

    # -- finalisation ------------------------------------------
    def finalize(self, md5_hex: str, sha1_hex: str) -> None:
        if self._buf:
            self._emit_chunk(bytes(self._buf))
            self._buf.clear()
        self._close_sectors_and_tables(last=True)
        if sha1_hex:
            dg = bytes.fromhex(md5_hex) + bytes.fromhex(sha1_hex)
            dg = dg.ljust(76, b"\x00")
            dg += struct.pack("<I", zlib.adler32(dg))
            self._write_section("digest", dg)
        h = bytes.fromhex(md5_hex).ljust(16, b"\x00") + b"\x00" * 16
        h += struct.pack("<I", zlib.adler32(h))
        self._write_section("hash", h)
        self._write_section("done", b"", self_ref=True)
        self._fh.close()

    # -- section helpers -------------------------------------
    def _write_section(self, stype: str, body: bytes,
                       self_ref: bool = False) -> None:
        here = self._fh.tell()
        size = 76 + len(body)
        nxt = here if self_ref else here + size
        desc = bytearray(76)
        desc[0:len(stype)] = stype.encode()
        struct.pack_into("<QQ", desc, 16, nxt, size)
        struct.pack_into("<I", desc, 72, zlib.adler32(bytes(desc[:72])))
        self._fh.write(bytes(desc) + body)

    def _patch_desc(self, pos: int, stype: bytes, nxt: int, size: int) -> None:
        cur = self._fh.tell()
        desc = bytearray(76)
        desc[0:len(stype)] = stype
        struct.pack_into("<QQ", desc, 16, nxt, size)
        struct.pack_into("<I", desc, 72, zlib.adler32(bytes(desc[:72])))
        self._fh.seek(pos)
        self._fh.write(bytes(desc))
        self._fh.seek(cur)

    def _volume(self) -> bytes:
        v = bytearray(1052)
        struct.pack_into("<B3xIIII", v, 0, 1, self.total_chunks, self.spc,
                         self.bps, self.media_size // self.bps)
        struct.pack_into("<I", v, 1048, zlib.adler32(bytes(v[:1048])))
        return bytes(v)

    def _header2(self) -> bytes:
        m = self.meta
        keys = ["a", "c", "n", "e", "t", "av", "ov", "m", "u", "p"]
        vals = [m.get("description", ""), m.get("case_number", ""),
                m.get("evidence_number", ""), m.get("examiner", ""),
                m.get("notes", ""), f"acquisition_image {m.get('version','')}",
                m.get("os", ""), str(int(m.get("acquired", time.time()))),
                str(int(time.time())), "0"]
        text = "3\nmain\n" + "\t".join(keys) + "\n" + "\t".join(vals) + "\n\n"
        return zlib.compress(b"\xff\xfe" + text.encode("utf-16-le"), 9)

    def _header(self) -> bytes:
        m = self.meta
        keys = ["c", "n", "a", "e", "t", "av", "ov", "m", "u", "p"]
        vals = [m.get("case_number", ""), m.get("evidence_number", ""),
                m.get("description", ""), m.get("examiner", ""),
                m.get("notes", ""), f"acquisition_image {m.get('version','')}",
                m.get("os", ""), str(int(m.get("acquired", time.time()))),
                str(int(time.time())), "0"]
        text = "1\nmain\n" + "\t".join(keys) + "\r\n" + "\t".join(vals) + "\r\n\r\n"
        return zlib.compress(text.encode("latin-1", "replace"), 9)
