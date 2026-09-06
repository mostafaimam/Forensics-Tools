"""Plugins for UsrClass.dat (per-user shell state - shellbags, jumplist IDs)."""

from __future__ import annotations

import struct

from windows_registry.hive import RegistryHive
from windows_registry.plugins._base import (
    NTUSER,
    USRCLASS,
    dt_to_iso,
    first_key,
    mrulistex_order,
    plugin,
    subkey,
)


def _dosdate(raw: bytes, off: int) -> str:
    if off + 4 > len(raw):
        return ""
    d, t = struct.unpack_from("<HH", raw, off)
    if d == 0:
        return ""
    year = ((d >> 9) & 0x7F) + 1980
    month = (d >> 5) & 0x0F
    day = d & 0x1F
    hh = (t >> 11) & 0x1F
    mm = (t >> 5) & 0x3F
    ss = (t & 0x1F) * 2
    try:
        return f"{year:04d}-{month:02d}-{day:02d}T{hh:02d}:{mm:02d}:{ss:02d}Z"
    except ValueError:
        return ""


def _shell_item_name(raw: bytes) -> tuple[str, str]:
    """Return (name, kind) for a single shell-item blob (without the 2-byte size)."""
    if len(raw) < 3:
        return ("", "unknown")
    typ = raw[2]
    if typ in (0x31, 0x32, 0x35, 0x36, 0xB1):  # file/dir entry
        # 0x2..: type, 0x4: u32 size, 0x8: dos mtime, 0xC: attrs, 0xE: name
        mtime = _dosdate(raw, 8)
        name = b""
        i = 14
        while i + 1 < len(raw) and raw[i:i + 1] != b"\x00":
            name += raw[i:i + 1]
            i += 1
        try:
            short = name.decode("mbcs", "replace")
        except LookupError:
            short = name.decode("latin-1", "replace")
        kind = "directory" if typ in (0x31, 0x35, 0xB1) else "file"
        return (f"{short} (m={mtime})" if mtime else short, kind)
    if typ == 0x1F:  # root / known folder
        return ("<root>", "root")
    if typ == 0x2F:  # volume
        drive = raw[3:6].decode("latin-1", "ignore").strip("\x00")
        return (drive, "volume")
    return ("", f"type-0x{typ:02x}")


@plugin("shellbags", "Shellbags - folders browsed in Explorer (BagMRU tree)",
        (USRCLASS, NTUSER))
def shellbags(hive: RegistryHive):
    base = first_key(
        hive,
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BagMRU")
    if not base:
        return []
    rows = []

    def walk(key, prefix):
        vals = {v.name: v for v in key.values()}
        order = mrulistex_order(vals["MRUListEx"].raw_data
                                if "MRUListEx" in vals else b"")
        for pos, idx in enumerate(order):
            v = vals.get(str(idx))
            raw = v.raw_data if v and isinstance(
                v.raw_data, (bytes, bytearray)) else b""
            name, kind = _shell_item_name(bytes(raw))
            path = f"{prefix}\\{name}" if name else prefix
            child = subkey(key, str(idx))
            rows.append({
                "path": path,
                "kind": kind,
                "mru_position": pos,
                "slot": str(idx),
                "key_last_written": dt_to_iso(child.last_written)
                if child else dt_to_iso(key.last_written),
            })
            if child:
                walk(child, path)

    walk(base, "Desktop")
    return rows
