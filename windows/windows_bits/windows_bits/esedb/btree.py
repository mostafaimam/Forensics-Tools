"""B-tree traversal: from an FDP page, yield every leaf entry."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from windows_bits.esedb.pages import FLAG_NEW_RECORD_FORMAT, Pager


@dataclass
class LeafEntry:
    key: bytes           # local page key (not the fully-assembled key)
    common_key: bytes
    data: bytes          # the entry data (record / branch target / LV chunk)


def _common_key_size(page) -> int:
    """Tag 0 on a NEW_RECORD_FORMAT page holds the common-page-key size."""
    if page.flags & FLAG_NEW_RECORD_FORMAT and page.tags:
        b = page.tag_bytes(0)
        if len(b) >= 2:
            return struct.unpack_from("<H", b, 0)[0]
    return 0


def _iter_page_entries(page, common_key_prefix: bytes):
    ckp_size = _common_key_size(page)
    common = common_key_prefix[:ckp_size] if ckp_size else b""
    for i in range(1, len(page.tags)):
        tag = page.tags[i]
        entry = page.tag_bytes(i)
        pos = 0
        local_common = common
        if tag.flags & 0x04 and len(entry) >= 2:      # entry has common key
            common_sz = struct.unpack_from("<H", entry, 0)[0]
            local_common = common_key_prefix[:common_sz]
            pos = 2
        if pos + 2 > len(entry):
            continue
        local_key_size = struct.unpack_from("<H", entry, pos)[0]
        pos += 2
        key = entry[pos:pos + local_key_size]
        pos += local_key_size
        yield tag, local_common, key, entry[pos:]


def walk_leaves(pager: Pager, fdp_page_number: int, *, _depth: int = 0):
    """Yield :class:`LeafEntry` for every leaf under *fdp_page_number*."""
    if _depth > 64:
        return
    try:
        page = pager.read(fdp_page_number)
    except Exception:                        # noqa: BLE001 tolerate bad page
        return
    if page.is_empty() or page.is_space_tree():
        return

    if page.is_leaf():
        for _tag, common, key, data in _iter_page_entries(page, b""):
            yield LeafEntry(key=key, common_key=common, data=data)
        return

    # branch page: each entry's data ends with a u32 child page number
    children: list[int] = []
    for _tag, _common, _key, data in _iter_page_entries(page, b""):
        if len(data) >= 4:
            children.append(struct.unpack_from("<I", data, len(data) - 4)[0])
    for child in children:
        if child and child != fdp_page_number:
            yield from walk_leaves(pager, child, _depth=_depth + 1)


def walk_leaves_via_siblings(pager: Pager, fdp_page_number: int):
    """Alternative: find the left-most leaf, then follow ``next_page``.

    More tolerant of a branch page whose child pointers are damaged.
    """
    seen: set[int] = set()
    page_no = fdp_page_number
    for _ in range(64):
        try:
            page = pager.read(page_no)
        except Exception:                    # noqa: BLE001
            return
        if page.is_leaf() or page.is_empty():
            break
        # take the first child
        first_child = None
        for _t, _c, _k, data in _iter_page_entries(page, b""):
            if len(data) >= 4:
                first_child = struct.unpack_from("<I", data,
                                                 len(data) - 4)[0]
                break
        if not first_child or first_child in seen:
            return
        seen.add(first_child)
        page_no = first_child

    while page_no and page_no not in seen:
        seen.add(page_no)
        try:
            page = pager.read(page_no)
        except Exception:                    # noqa: BLE001
            return
        if not page.is_leaf():
            return
        for _tag, common, key, data in _iter_page_entries(page, b""):
            yield LeafEntry(key=key, common_key=common, data=data)
        page_no = page.next_page if page.next_page > 0 else 0
