"""Binary parser for a single (decompressed) FSEvents log stream."""

from __future__ import annotations

import gzip
import struct
import zlib
from dataclasses import dataclass, field

_MAGICS = {b"1SLD": 1, b"2SLD": 2, b"3SLD": 3}   # 'DLS1' etc., little-endian

# on-disk record flags (not the FSEvents API flags)
FLAGS = [
    (0x00000001, "FolderEvent"),
    (0x00000002, "Mount"),
    (0x00000004, "Unmount"),
    (0x00000020, "EndOfTransaction"),
    (0x00000800, "LastHardLinkRemoved"),
    (0x00001000, "HardLink"),
    (0x00004000, "SymbolicLink"),
    (0x00008000, "FileEvent"),
    (0x00010000, "PermissionChange"),
    (0x00020000, "XattrModified"),
    (0x00040000, "XattrRemoved"),
    (0x00100000, "DocumentRevisioning"),
    (0x00400000, "Created"),
    (0x00800000, "Removed"),
    (0x01000000, "InodeMetaMod"),
    (0x02000000, "Renamed"),
    (0x04000000, "Modified"),
    (0x08000000, "Exchange"),
    (0x10000000, "FinderInfoMod"),
    (0x20000000, "FolderCreated"),
    (0x40000000, "FolderRemoved"),
    (0x80000000, "IdChanged"),
]


def decode_flags(v: int) -> list[str]:
    return [name for bit, name in FLAGS if v & bit] or [f"0x{v:08x}"]


@dataclass
class Record:
    path: str
    event_id: int
    flags: int
    flag_names: list
    node_id: int
    version: int
    source_file: str = ""
    approx_time: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "approx_time": self.approx_time, "path": self.path,
            "flags": ",".join(self.flag_names), "flags_hex": f"0x{self.flags:08x}",
            "event_id": self.event_id, "node_id": self.node_id or "",
            "dls_version": self.version, "source_file": self.source_file,
            "notable": ";".join(self.notable),
        }


def _gunzip_all(data: bytes) -> bytes:
    """Handle single- or multi-member gzip; fall back to raw."""
    if data[:2] != b"\x1f\x8b":
        return data
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n and data[pos:pos + 2] == b"\x1f\x8b":
        try:
            d = zlib.decompressobj(31)
            out += d.decompress(data[pos:])
            out += d.flush()
            consumed = n - len(d.unused_data)
            if consumed <= pos:
                break
            pos = consumed
        except zlib.error:
            try:
                return gzip.decompress(data)
            except OSError:
                break
    return bytes(out)


def parse_stream(raw: bytes, source_file: str = ""):
    data = _gunzip_all(raw)
    n = len(data)
    pos = 0
    while pos + 12 <= n:
        magic = data[pos:pos + 4]
        version = _MAGICS.get(magic)
        if version is None:
            # try to resync to the next magic
            nxt = min((data.find(m, pos + 1) for m in _MAGICS
                       if data.find(m, pos + 1) >= 0), default=-1)
            if nxt < 0:
                return
            pos = nxt
            continue
        # header: magic(4) unknown(4) page_stream_size(4)
        page_size = struct.unpack_from("<I", data, pos + 8)[0]
        page_end = pos + page_size if 12 < page_size <= n - pos else n
        rp = pos + 12
        while rp < page_end:
            z = data.find(b"\x00", rp, page_end)
            if z < 0:
                break
            path = data[rp:z].decode("utf-8", "replace")
            rp = z + 1
            if version == 1:
                if rp + 12 > page_end:
                    break
                eid, flags = struct.unpack_from("<QI", data, rp)
                rp += 12
                node = 0
            else:
                if rp + 20 > page_end:
                    break
                eid, flags, node = struct.unpack_from("<QIQ", data, rp)
                rp += 20
            if not path and flags == 0:
                continue
            yield Record(path=path, event_id=eid, flags=flags,
                         flag_names=decode_flags(flags), node_id=node,
                         version=version, source_file=source_file)
        pos = page_end
