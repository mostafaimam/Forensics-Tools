"""Hand-build a tiny but structurally valid NTFS volume image for tests."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

SECTOR = 512
SPC = 8                       # sectors per cluster
CLUSTER = SECTOR * SPC        # 4096
REC = 1024                    # MFT record size
MFT_CLUSTER = 4
USN = b"\x11\x11"


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def _attr_resident(type_id: int, content: bytes, attr_id: int = 0,
                   name: str = "") -> bytes:
    name_b = name.encode("utf-16-le")
    header_len = 0x18 + len(name_b)
    header_len = (header_len + 7) & ~7
    content_off = header_len
    total = (content_off + len(content) + 7) & ~7
    h = bytearray(total)
    struct.pack_into("<IIBBHHH", h, 0, type_id, total, 0,
                     len(name), 0x18 if name else 0, 0, attr_id)
    struct.pack_into("<IH", h, 0x10, len(content), content_off)
    if name:
        h[0x18:0x18 + len(name_b)] = name_b
    h[content_off:content_off + len(content)] = content
    return bytes(h)


def _attr_nonresident(type_id: int, runlist: bytes, real_size: int,
                      last_vcn: int, alloc_size: int, attr_id: int = 0) -> bytes:
    run_off = 0x40
    total = (run_off + len(runlist) + 7) & ~7
    h = bytearray(total)
    struct.pack_into("<IIBBHHH", h, 0, type_id, total, 1, 0, 0, 0, attr_id)
    struct.pack_into("<QQHHI", h, 0x10, 0, last_vcn, run_off, 0, 0)
    struct.pack_into("<QQQ", h, 0x28, alloc_size, real_size, real_size)
    h[run_off:run_off + len(runlist)] = runlist
    return bytes(h)


def _std_info(dt: datetime) -> bytes:
    b = bytearray(72)
    t = ft(dt)
    struct.pack_into("<QQQQ", b, 0, t, t, t, t)
    return bytes(b)


def _file_name(parent_entry: int, parent_seq: int, name: str,
               size: int, is_dir: bool, dt: datetime) -> bytes:
    name_b = name.encode("utf-16-le")
    b = bytearray(66 + len(name_b))
    struct.pack_into("<Q", b, 0, parent_entry | (parent_seq << 48))
    t = ft(dt)
    struct.pack_into("<QQQQ", b, 8, t, t, t, t)
    struct.pack_into("<QQ", b, 40, (size + CLUSTER - 1) & ~(CLUSTER - 1), size)
    struct.pack_into("<I", b, 56, 0x10000000 if is_dir else 0x00000020)
    b[64] = len(name)
    b[65] = 1  # Win32 namespace
    b[66:] = name_b
    return bytes(b)


def _runlist(length_clusters: int, start_lcn: int) -> bytes:
    ln = length_clusters.to_bytes(2, "little")
    off = start_lcn.to_bytes(2, "little", signed=True)
    return bytes([0x22]) + ln + off


def make_record(number: int, seq: int, flags: int, attrs: list[bytes]) -> bytes:
    body = bytearray(REC)
    body[0:4] = b"FILE"
    struct.pack_into("<HH", body, 4, 0x30, (REC // SECTOR) + 1)
    struct.pack_into("<H", body, 16, seq)
    struct.pack_into("<H", body, 18, 1)
    struct.pack_into("<H", body, 20, 0x38)
    struct.pack_into("<H", body, 22, flags)
    struct.pack_into("<I", body, 28, REC)
    struct.pack_into("<I", body, 44, number)

    off = 0x38
    for a in attrs:
        body[off:off + len(a)] = a
        off += len(a)
    struct.pack_into("<I", body, off, 0xFFFFFFFF)
    off += 8
    struct.pack_into("<I", body, 24, off)

    # update sequence array + fixup
    usa_off = 0x30
    body[usa_off:usa_off + 2] = USN
    for i in range(REC // SECTOR):
        sec_end = (i + 1) * SECTOR
        body[usa_off + 2 + i * 2: usa_off + 4 + i * 2] = body[sec_end - 2:sec_end]
        body[sec_end - 2:sec_end] = USN
    return bytes(body)


def build_ntfs_image() -> tuple[bytes, dict]:
    """Returns (image_bytes, {name: expected_content})."""
    total_clusters = 64
    total_sectors = total_clusters * SPC
    img = bytearray(total_clusters * CLUSTER)

    # boot sector
    bs = img
    bs[3:11] = b"NTFS    "
    struct.pack_into("<H", bs, 0x0B, SECTOR)
    bs[0x0D] = SPC
    struct.pack_into("<Q", bs, 0x28, total_sectors)
    struct.pack_into("<Q", bs, 0x30, MFT_CLUSTER)
    struct.pack_into("<Q", bs, 0x38, 8)
    struct.pack_into("<b", bs, 0x40, -10)          # 2^10 = 1024-byte records
    struct.pack_into("<Q", bs, 0x48, 0xDEADBEEFCAFEF00D)
    bs[510:512] = b"\x55\xaa"

    dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    now = datetime(2024, 6, 2, 9, 30, 0, tzinfo=timezone.utc)

    hello = b"hello from a live NTFS file\n" * 3
    secret = b"THIS FILE WAS DELETED BUT NOT OVERWRITTEN\n" * 40  # > 1 cluster

    def si(d):
        return _attr_resident(0x10, _std_info(d))

    def fn(parent, name, size, is_dir, d):
        return _attr_resident(0x30, _file_name(parent, 5, name, size, is_dir, d))

    records: dict[int, bytes] = {}

    # rec 0: $MFT - non-resident $DATA covering clusters 4..7 (8 records)
    records[0] = make_record(0, 1, 0x01, [
        si(dt),
        _attr_nonresident(0x80, _runlist(8, MFT_CLUSTER), 8 * CLUSTER, 7,
                          8 * CLUSTER),
    ])

    # rec 5: root directory
    records[5] = make_record(5, 5, 0x03, [
        si(dt),
        fn(5, ".", 0, True, dt),
        _attr_resident(0x90, b"\x00" * 16, name="$I30"),  # minimal $INDEX_ROOT
    ])

    # rec 6: allocated file, resident data
    records[24] = make_record(24, 1, 0x01, [
        si(now),
        fn(5, "hello.txt", len(hello), False, now),
        _attr_resident(0x80, hello),
    ])

    # rec 7: DELETED file, non-resident data at cluster 20
    del_lcn = 20
    img[del_lcn * CLUSTER: del_lcn * CLUSTER + len(secret)] = secret
    last_vcn = (len(secret) + CLUSTER - 1) // CLUSTER - 1
    records[25] = make_record(25, 2, 0x00, [
        si(dt),
        fn(5, "secret.txt", len(secret), False, dt),
        _attr_nonresident(0x80, _runlist(last_vcn + 1, del_lcn), len(secret),
                          last_vcn, (last_vcn + 1) * CLUSTER),
    ])

    mft_base = MFT_CLUSTER * CLUSTER
    for num, rec in records.items():
        img[mft_base + num * REC: mft_base + num * REC + REC] = rec
    # remaining records 1-4 left as zero (parser skips bad signatures)

    return bytes(img), {
        "hello.txt": hello,
        "secret.txt": secret,
    }
