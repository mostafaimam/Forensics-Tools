"""Binary parsers for thumbcache_*.db and thumbcache_idx.db."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

SIG = b"CMMM"
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# format version -> friendly Windows name
_VERSIONS = {
    0x14: "Windows Vista", 0x15: "Windows 7", 0x1A: "Windows 8",
    0x1C: "Windows 8.1", 0x1E: "Windows 8.1 U1", 0x1F: "Windows 10",
    0x20: "Windows 10",
}


class ThumbError(Exception):
    pass


def _ft(ticks: int) -> str:
    if ticks <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _image_format(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:2] == b"BM":
        return "bmp"
    if data[:4] in (b"RIFF",) and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] == b"GIF8":
        return "gif"
    return ""


@dataclass
class Thumbnail:
    cache_id: int             # 64-bit hash
    identifier: str
    fmt: str
    width: int
    height: int
    data_size: int
    data_offset: int          # offset of the image data within the .db
    db_name: str
    last_modified: str = ""   # from the index
    idx_flags: int = 0
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "cache_id": f"{self.cache_id:016x}",
            "identifier": self.identifier, "format": self.fmt,
            "width": self.width or "", "height": self.height or "",
            "data_size": self.data_size, "db": self.db_name,
            "last_modified": self.last_modified,
            "idx_flags": f"0x{self.idx_flags:x}" if self.idx_flags else "",
            "notable": ";".join(self.notable),
        }


@dataclass
class CacheFile:
    version: int
    version_name: str
    cache_type: int
    entries: list = field(default_factory=list)     # Thumbnail
    warnings: list = field(default_factory=list)


def parse_cache(data: bytes, db_name: str = "") -> CacheFile:
    if len(data) < 24 or data[:4] != SIG:
        raise ThumbError("not a thumbcache file (missing CMMM signature)")
    version = struct.unpack_from("<I", data, 4)[0]
    cache_type = struct.unpack_from("<I", data, 8)[0]
    cf = CacheFile(version=version,
                   version_name=_VERSIONS.get(version, f"0x{version:x}"),
                   cache_type=cache_type)

    # the header size varies by version and the pointer is not reliable
    # across builds - just find the first cache entry by its own signature.
    off = data.find(SIG, 4)
    if off < 0:
        off = len(data)

    n = len(data)
    guard = 0
    while off + 8 <= n and guard < 200000:
        guard += 1
        if data[off:off + 4] != SIG:
            # try to resync to the next CMMM
            nxt = data.find(SIG, off + 4)
            if nxt < 0:
                break
            off = nxt
            continue
        entry_size = struct.unpack_from("<I", data, off + 4)[0]
        if entry_size < 24 or off + entry_size > n:
            break
        t = _parse_entry(data, off, version, db_name)
        if t is not None:
            cf.entries.append(t)
        off += entry_size
        off += (8 - off % 8) % 8
    return cf


def _parse_entry(data: bytes, off: int, version: int,
                 db_name: str) -> Thumbnail | None:
    try:
        entry_hash = struct.unpack_from("<Q", data, off + 8)[0]
        pos = off + 16
        if version > 0x14:
            pos += 4              # extension (Win7+) - 4 bytes "jpg\0" etc
        id_size = struct.unpack_from("<I", data, pos)[0]
        pad_size = struct.unpack_from("<I", data, pos + 4)[0]
        data_size = struct.unpack_from("<I", data, pos + 8)[0]
        pos += 12
        width = height = 0
        if version >= 0x1C:
            width, height = struct.unpack_from("<HH", data, pos)
            pos += 4
            pos += 4             # unknown
        pos += 8                 # data checksum
        pos += 8                 # header checksum
        if id_size > 4096 or pos + id_size > len(data):
            return None
        identifier = data[pos:pos + id_size].decode("utf-16-le", "replace")
        pos += id_size + pad_size
        blob = data[pos:pos + data_size] if data_size and \
            pos + data_size <= len(data) else b""
        return Thumbnail(cache_id=entry_hash, identifier=identifier,
                         fmt=_image_format(blob), width=width, height=height,
                         data_size=data_size, data_offset=pos,
                         db_name=db_name)
    except struct.error:
        return None


# --------------------------------------------------------------------- index
@dataclass
class IndexEntry:
    cache_id: int
    last_modified: str
    flags: int
    cache_offsets: list       # per-size offsets (0xFFFFFFFF = not present)


def parse_index(data: bytes) -> dict[int, IndexEntry]:
    """thumbcache_idx.db - the entry layout has varied across Windows
    versions; this reads the common {id(8), last-modified(8), flags(4),
    cache offsets} shape and resyncs on a run of 0xFF cache offsets.
    """
    out: dict[int, IndexEntry] = {}
    if len(data) < 24 or data[:4] != SIG:
        return out
    header_size = 24
    entry_size = 32
    n_offsets = (entry_size - 20) // 4
    off = header_size
    n = len(data)
    while off + entry_size <= n:
        cid = struct.unpack_from("<Q", data, off)[0]
        ft = struct.unpack_from("<Q", data, off + 8)[0]
        flags = struct.unpack_from("<I", data, off + 16)[0]
        offs = list(struct.unpack_from(f"<{n_offsets}I", data, off + 20))
        if cid != 0:
            out[cid] = IndexEntry(cache_id=cid, last_modified=_ft(ft),
                                  flags=flags, cache_offsets=offs)
        off += entry_size
    return out
