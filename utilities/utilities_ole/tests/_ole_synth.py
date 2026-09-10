"""Write a small OLE2 compound file with a real directory tree (for .msg)."""

from __future__ import annotations

import struct

SECTOR = 512
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
CUTOFF = 4096


class _Node:
    def __init__(self, name, etype):
        self.name = name
        self.etype = etype          # 1 storage, 2 stream, 5 root
        self.data = b""
        self.children: list[_Node] = []
        self.left = self.right = self.child = NOSTREAM
        self.start = ENDOFCHAIN
        self.size = 0
        self.id = -1


def _flatten(root: _Node) -> list[_Node]:
    """Assign ids; link siblings as a right-leaning list; set storage .child."""
    order: list[_Node] = []

    def visit(n: _Node):
        n.id = len(order)
        order.append(n)
        kids = n.children
        for k in kids:
            visit(k)
        if kids:
            n.child = kids[0].id
            for a, b in zip(kids, kids[1:]):
                a.right = b.id
    visit(root)
    return order


def build_msg_ole(top: dict[str, bytes],
                  storages: dict[str, dict[str, bytes]] | None = None) -> bytes:
    root = _Node("Root Entry", 5)
    for name, data in top.items():
        n = _Node(name, 2)
        n.data = data
        root.children.append(n)
    for sname, streams in (storages or {}).items():
        s = _Node(sname, 1)
        for cn, cd in streams.items():
            c = _Node(cn, 2)
            c.data = cd
            s.children.append(c)
        root.children.append(s)

    nodes = _flatten(root)
    MINI = 64

    # small streams (< CUTOFF) -> mini-stream; large -> main FAT
    mini_stream = bytearray()
    minifat: list[int] = []
    big = []
    for n in nodes:
        if n.etype != 2:
            continue
        if len(n.data) < CUTOFF:
            n.size = len(n.data)
            n.start = len(mini_stream) // MINI
            padded = n.data + b"\x00" * ((-len(n.data)) % MINI or 0)
            nmini = max(len(padded) // MINI, 1)
            for i in range(nmini):
                minifat.append(n.start + i + 1 if i < nmini - 1 else ENDOFCHAIN)
            mini_stream += padded or b"\x00" * MINI
        else:
            big.append(n)

    n_dir_sectors = (len(nodes) + 3) // 4
    minifat_bytes = (len(minifat) * 4 + SECTOR - 1) // SECTOR * SECTOR
    n_minifat_sectors = minifat_bytes // SECTOR
    n_ministream_sectors = (len(mini_stream) + SECTOR - 1) // SECTOR

    dir_first = 1
    minifat_first = dir_first + n_dir_sectors
    ministream_first = minifat_first + n_minifat_sectors
    data_first = ministream_first + n_ministream_sectors

    root.start = ministream_first if mini_stream else ENDOFCHAIN
    root.size = len(mini_stream)

    layout = []
    cur = data_first
    for n in big:
        cnt = max((len(n.data) + SECTOR - 1) // SECTOR, 1)
        n.start, n.size = cur, len(n.data)
        layout.append((n, n.data, cnt))
        cur += cnt
    total = cur

    fat = [FREESECT] * (max(total, SECTOR // 4) + SECTOR // 4)
    fat[0] = FATSECT

    def chain(start, count):
        for i in range(count):
            fat[start + i] = start + i + 1 if i < count - 1 else ENDOFCHAIN

    chain(dir_first, n_dir_sectors)
    if n_minifat_sectors:
        chain(minifat_first, n_minifat_sectors)
    if n_ministream_sectors:
        chain(ministream_first, n_ministream_sectors)
    for n, _d, cnt in layout:
        chain(n.start, cnt)

    header = bytearray(SECTOR)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HH", header, 0x1A, 0x003E, 0x0003)
    struct.pack_into("<H", header, 0x1E, 9)
    struct.pack_into("<H", header, 0x20, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, dir_first)
    struct.pack_into("<I", header, 0x38, CUTOFF)
    struct.pack_into("<I", header, 0x3C,
                     minifat_first if n_minifat_sectors else ENDOFCHAIN)
    struct.pack_into("<I", header, 0x40, n_minifat_sectors)
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)
    struct.pack_into("<I", header, 0x48, 0)
    struct.pack_into("<I", header, 0x4C, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + i * 4, FREESECT)
    fat_sector = b"".join(struct.pack("<I", v) for v in fat[:SECTOR // 4])

    directory = bytearray()
    for n in nodes:
        b = bytearray(128)
        nm = n.name.encode("utf-16-le") + b"\x00\x00"
        b[:len(nm)] = nm
        struct.pack_into("<H", b, 64, len(nm))
        b[66] = n.etype
        b[67] = 1
        struct.pack_into("<III", b, 68, n.left, n.right, n.child)
        start = n.start
        if n.etype == 2 and n.size == 0:
            start = ENDOFCHAIN
        struct.pack_into("<I", b, 116, start)
        struct.pack_into("<Q", b, 120, n.size)
        directory += b
    while len(directory) < n_dir_sectors * SECTOR:
        directory += bytes(128)

    minifat_raw = b"".join(struct.pack("<I", v) for v in minifat)
    minifat_raw = minifat_raw.ljust(n_minifat_sectors * SECTOR, b"\x00")
    ministream_raw = bytes(mini_stream).ljust(
        n_ministream_sectors * SECTOR, b"\x00")

    body = bytearray()
    for _n, data, cnt in layout:
        body += data + b"\x00" * (cnt * SECTOR - len(data))

    return (bytes(header) + fat_sector + bytes(directory) + minifat_raw
            + ministream_raw + bytes(body))


def substg(tag: str, ptype: str, value) -> tuple[str, bytes]:
    name = f"__substg1.0_{tag}{ptype}"
    if isinstance(value, bytes):
        return name, value
    if ptype in ("001F", "101F"):
        return name, value.encode("utf-16-le")
    return name, value.encode("cp1252")


def properties_stream(times: dict[int, int], top_level: bool = True) -> bytes:
    hdr = b"\x00" * (32 if top_level else 24)
    out = bytearray(hdr)
    for tag, ticks in times.items():
        out += struct.pack("<HHI", tag, 0x0040, 0)
        out += struct.pack("<Q", ticks)
    return bytes(out)
