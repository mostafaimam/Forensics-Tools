"""High-level hive: key tree walk, path lookup, deleted-cell recovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from windows_bam.hive.cells import (
    KeyNode,
    ValueNode,
    iter_subkey_offsets,
    iter_value_offsets,
)
from windows_bam.hive.regf import Hive as RawHive
from windows_bam.hive.regf import HiveError


@dataclass
class Key:
    node: KeyNode
    path: str
    hive: "RegistryHive" = field(repr=False, default=None)

    @property
    def name(self) -> str:
        return self.node.name

    @property
    def last_written(self):
        return self.node.last_written

    @property
    def deleted(self) -> bool:
        return not self.node.allocated

    def values(self) -> list[ValueNode]:
        return self.hive.values_of(self.node)

    def subkeys(self) -> Iterator["Key"]:
        yield from self.hive.subkeys_of(self)


class RegistryHive:
    def __init__(self, data: bytes) -> None:
        self.raw = RawHive(data)
        self.base = self.raw.base

    # -- tree walk ------------------------------------------------
    def root(self) -> Key:
        node = KeyNode.parse(
            self.raw.cell_data(self.base.root_cell_offset),
            self.base.root_cell_offset)
        return Key(node, node.name, self)

    def subkeys_of(self, key: Key) -> Iterator[Key]:
        for off in iter_subkey_offsets(self.raw, key.node.subkeys_list_offset):
            try:
                child = KeyNode.parse(self.raw.cell_data(off), off)
            except (HiveError, ValueError):
                continue
            yield Key(child, f"{key.path}\\{child.name}" if key.path else child.name,
                      self)

    def values_of(self, node: KeyNode) -> list[ValueNode]:
        out = []
        for off in iter_value_offsets(self.raw, node.values_list_offset,
                                      node.value_count):
            try:
                out.append(ValueNode.parse(self.raw.cell_data(off), off, self.raw))
            except (HiveError, ValueError):
                continue
        return out

    def walk(self, key: Key | None = None) -> Iterator[Key]:
        key = key or self.root()
        yield key
        for sub in self.subkeys_of(key):
            yield from self.walk(sub)

    def get(self, path: str) -> Key | None:
        """Resolve a back-slash-separated key path (case-insensitive), starting
        below the root."""
        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        cur = self.root()
        if parts and parts[0].lower() == cur.name.lower():
            parts = parts[1:]
        for part in parts:
            nxt = None
            for sub in self.subkeys_of(cur):
                if sub.name.lower() == part.lower():
                    nxt = sub
                    break
            if nxt is None:
                return None
            cur = nxt
        return cur

    # -- deleted recovery --------------------------------------
    def recover_deleted(self) -> Iterator[Key]:
        """Yield orphan ``nk`` records found in free cells."""
        for cell in self.raw.iter_cells():
            if cell.allocated or cell.signature != b"nk":
                continue
            try:
                node = KeyNode.parse(cell.data, cell.offset, allocated=False)
            except (HiveError, ValueError):
                continue
            if not node.name or not node.name.isprintable():
                continue
            yield Key(node, f"<deleted>\\{node.name}", self)

    def recover_deleted_values(self) -> Iterator[ValueNode]:
        for cell in self.raw.iter_cells():
            if cell.allocated or cell.signature != b"vk":
                continue
            try:
                v = ValueNode.parse(cell.data, cell.offset, self.raw,
                                    allocated=False)
            except (HiveError, ValueError):
                continue
            yield v
