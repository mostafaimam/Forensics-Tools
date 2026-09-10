"""VBA macro detection and source extraction ([MS-OVBA])."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_VBA_STORAGES = ("Macros", "_VBA_PROJECT_CUR", "VBA")


def decompress(data: bytes) -> bytes:
    """MS-OVBA 2.4.1.3.2 decompression of a Compressed Container."""
    if not data or data[0] != 0x01:
        return b""
    out = bytearray()
    pos = 1
    n = len(data)
    while pos < n:
        header = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        chunk_size = (header & 0x0FFF) + 3
        compressed = bool(header & 0x8000)
        chunk_end = min(pos + chunk_size - 2, n)
        if not compressed:
            out += data[pos:pos + 4096]
            pos += 4096
            continue
        start = len(out)
        while pos < chunk_end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not (flags >> bit) & 1:
                    out.append(data[pos])
                    pos += 1
                else:
                    token = struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                    diff = len(out) - start
                    bit_count = max(4, (diff - 1).bit_length()) if diff > 1 \
                        else 4
                    length_mask = 0xFFFF >> bit_count
                    offset_mask = ~length_mask & 0xFFFF
                    length = (token & length_mask) + 3
                    offset = ((token & offset_mask) >> (16 - bit_count)) + 1
                    src = len(out) - offset
                    for _ in range(length):
                        out.append(out[src])
                        src += 1
    return bytes(out)


@dataclass
class Module:
    name: str = ""
    stream: str = ""
    offset: int = 0
    source: str = ""
    kind: str = ""


@dataclass
class VbaProject:
    present: bool = False
    modules: list = field(default_factory=list)
    project_refs: list = field(default_factory=list)
    error: str = ""


def _find_vba_root(ole):
    for path, e in ole.walk():
        parts = path.split("/")
        if parts and parts[0] in _VBA_STORAGES:
            # look for a 'dir' stream under this storage
            return parts[0]
    return None


def extract(ole) -> VbaProject:
    vp = VbaProject()
    root = _find_vba_root(ole)
    if root is None:
        return vp
    tree = {p.lower(): p for p, _e in ole.walk()}
    dir_path = None
    for cand in (f"{root}/VBA/dir", f"{root}/dir"):
        if cand.lower() in tree:
            dir_path = tree[cand.lower()]
            break
    if dir_path is None:
        return vp
    vp.present = True
    try:
        dir_raw = decompress(ole.read_path(dir_path))
    except Exception as e:  # noqa: BLE001
        vp.error = f"dir stream: {e}"
        return vp

    mods: dict[str, Module] = {}
    pos = 0
    cur = None
    n = len(dir_raw)
    while pos + 6 <= n:
        rec_id, rec_size = struct.unpack_from("<HI", dir_raw, pos)
        pos += 6
        payload = dir_raw[pos:pos + rec_size]
        pos += rec_size
        if rec_id == 0x0019:                       # MODULENAME
            name = payload.decode("latin-1", "replace")
            cur = Module(name=name)
            mods[name] = cur
        elif rec_id == 0x001A and cur:            # MODULESTREAMNAME
            cur.stream = payload.decode("latin-1", "replace")
        elif rec_id == 0x0031 and cur:            # MODULEOFFSET
            if len(payload) >= 4:
                cur.offset = struct.unpack_from("<I", payload, 0)[0]
        elif rec_id in (0x0021, 0x0022) and cur:  # MODULETYPE proc/doc
            cur.kind = "procedural" if rec_id == 0x0021 else "document/class"
        elif rec_id == 0x0010:                    # PROJECT terminator
            break

    for m in mods.values():
        stream_path = None
        for cand in (f"{root}/VBA/{m.stream}", f"{root}/{m.stream}"):
            if cand.lower() in tree:
                stream_path = tree[cand.lower()]
                break
        if not stream_path:
            continue
        try:
            raw = ole.read_path(stream_path)
            m.source = decompress(raw[m.offset:]).rstrip(b"\x00").decode(
                "latin-1", "replace")
        except Exception:  # noqa: BLE001
            continue
    vp.modules = list(mods.values())
    return vp
