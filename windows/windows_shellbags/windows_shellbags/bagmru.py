"""Walk BagMRU / Bags from a UsrClass.dat or NTUSER.DAT hive."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from windows_shellbags import shellitems as _si
from windows_shellbags.hive import RegistryHive

_BAGMRU_PATHS = [
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",       # UsrClass
    r"Software\Microsoft\Windows\Shell\BagMRU",                      # NTUSER
    r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",               # legacy
    r"Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
]


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


@dataclass
class Bag:
    key_path: str = ""              # BagMRU\0\2\...
    depth: int = 0
    slot: str = ""                  # child slot number
    node_slot: str = ""            # NodeSlot value
    mru_position: int = -1          # position in MRUListEx (0 = most recent)
    last_written: str = ""         # key last-written (folder last interacted)
    item_type: str = ""
    name: str = ""                  # this level's name
    path: str = ""                  # full reconstructed path
    guid: str = ""
    created: str = ""
    modified: str = ""
    accessed: str = ""
    mft_entry: str = ""
    mft_sequence: str = ""
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "path": self.path, "name": self.name, "item_type": self.item_type,
            "guid": self.guid, "key_path": self.key_path, "depth": self.depth,
            "node_slot": self.node_slot, "mru_position":
            self.mru_position if self.mru_position >= 0 else "",
            "last_interacted": self.last_written,
            "created": self.created, "modified": self.modified,
            "accessed": self.accessed, "mft_entry": self.mft_entry,
            "mft_sequence": self.mft_sequence, "source": self.source,
            "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    bags: list = field(default_factory=list)
    hive_kind: str = ""
    root_key: str = ""
    errors: list = field(default_factory=list)


def _mru_order(key) -> dict[str, int]:
    for v in key.values():
        if v.name == "MRUListEx" and v.raw_data:
            raw = bytes(v.raw_data)
            order = {}
            pos = 0
            i = 0
            while pos + 4 <= len(raw):
                n = struct.unpack_from("<i", raw, pos)[0]
                if n == -1:
                    break
                order[str(n)] = i
                i += 1
                pos += 4
            return order
    return {}


def _node_slot(key) -> str:
    for v in key.values():
        if v.name.lower() == "nodeslot":
            return str(v.data if isinstance(v.data, int) else
                       int.from_bytes(bytes(v.raw_data or b""), "little"))
    return ""


def _item_name(item: dict) -> str:
    return (item.get("long_name") or item.get("name") or "").strip()


def _walk(key, parent_path, depth, res: Result, source: str, mru_parent):
    node_slot = _node_slot(key)
    order = _mru_order(key)
    # numbered values hold the shell items for this key's children
    child_items: dict[str, dict] = {}
    for v in key.values():
        if v.name.isdigit() and v.raw_data:
            items = _si.parse_idlist(bytes(v.raw_data))
            child_items[v.name] = items[0] if items else {"type": "empty"}

    for sub in key.subkeys():
        slot = sub.name
        if not slot.isdigit():
            continue
        item = child_items.get(slot, {"type": "empty"})
        name = _item_name(item)
        it_type = item.get("type", "")
        if it_type == "drive":
            seg = name if name.endswith("\\") else name + "\\"
            full = seg
        elif it_type in ("known-folder", "network", "root"):
            full = (parent_path + name) if parent_path else name
        else:
            full = (parent_path.rstrip("\\") + "\\" + name) if parent_path \
                else name

        kp_tail = sub.path.split("BagMRU", 1)[-1].lstrip("\\")
        b = Bag(key_path=f"{res.root_key}\\{kp_tail}" if kp_tail
                else res.root_key,
                depth=depth + 1, slot=slot, node_slot=_node_slot(sub),
                mru_position=order.get(slot, -1),
                last_written=_iso(sub.last_written),
                item_type=it_type, name=name or item.get("guid", ""),
                path=full,
                guid=item.get("guid", ""),
                created=item.get("created", ""),
                modified=item.get("modified", ""),
                accessed=item.get("accessed", ""),
                mft_entry=str(item.get("mft_entry", "") or ""),
                mft_sequence=str(item.get("mft_sequence", "") or ""),
                source=source)
        res.bags.append(b)
        _walk(sub, full, depth + 1, res, source, order.get(slot, -1))


def from_hive_bytes(data: bytes, source: str = "") -> Result:
    res = Result()
    try:
        hive = RegistryHive(data)
    except Exception as e:                        # noqa: BLE001 vendored lib
        res.errors.append(f"hive parse failed: {e}")
        return res

    key = None
    for p in _BAGMRU_PATHS:
        try:
            key = hive.get(p)
        except Exception:                        # noqa: BLE001 vendored lib
            key = None
        if key is not None:
            res.root_key = p
            res.hive_kind = ("UsrClass.dat" if "Local Settings" in p
                             else "NTUSER.DAT")
            break
    if key is None:
        res.errors.append("no BagMRU key found in this hive")
        return res

    try:
        _walk(key, "", 0, res, source or res.hive_kind, -1)
    except Exception as e:                        # noqa: BLE001
        res.errors.append(f"BagMRU walk failed: {e}")
    res.bags.sort(key=lambda b: (b.depth, b.path.lower()))
    return res


def from_hive_file(path) -> Result:
    from pathlib import Path
    return from_hive_bytes(Path(path).read_bytes(), str(path))
