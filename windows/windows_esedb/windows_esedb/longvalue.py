"""Assemble long values from a table's long-value B-tree."""

from __future__ import annotations

import struct

from windows_esedb.btree import walk_leaves, walk_leaves_via_siblings


class LongValueStore:
    def __init__(self, pager, lv_fdp_page: int):
        self.chunks: dict[int, list[tuple[int, bytes]]] = {}
        self.total: dict[int, int] = {}
        if not lv_fdp_page:
            return
        leaves = list(walk_leaves(pager, lv_fdp_page)) or \
            list(walk_leaves_via_siblings(pager, lv_fdp_page))
        for leaf in leaves:
            key = leaf.common_key + leaf.key
            if len(key) == 4:
                # header entry: LID (big-endian) -> total size (u32 LE in data)
                lid = struct.unpack(">I", key)[0]
                if len(leaf.data) >= 4:
                    self.total[lid] = struct.unpack("<I", leaf.data[:4])[0]
            elif len(key) >= 8:
                lid = struct.unpack(">I", key[:4])[0]
                offset = struct.unpack(">I", key[4:8])[0]
                self.chunks.setdefault(lid, []).append((offset, leaf.data))

    def get(self, lid: int) -> bytes:
        parts = sorted(self.chunks.get(lid, []))
        return b"".join(p[1] for p in parts)
