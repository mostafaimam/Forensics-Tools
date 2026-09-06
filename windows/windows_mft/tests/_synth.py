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


def _std_info(dt: datetime, *, distinct: bool = False) -> bytes:
    """All four stamps equal (timestomp-style) unless *distinct*, in which case
    they get realistic, differing sub-second values."""
    b = bytearray(72)
    if distinct:
        c = ft(dt) + 1234567
        m = ft(dt) + 89_0001234
        r = ft(dt) + 89_0005678
        a = ft(dt) + 250_0009999
        struct.pack_into("<QQQQ", b, 0, c, m, r, a)
    else:
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

    def si(d, distinct=False):
        return _attr_resident(0x10, _std_info(d, distinct=distinct))

    def fn(parent, name, size, is_dir, d):
        return _attr_resident(0x30, _file_name(parent, 5, name, size, is_dir, d))

    records: dict[int, bytes] = {}

    # rec 0: $MFT - non-resident $DATA covering clusters 4..7 (8 records)
    records[0] = make_record(0, 1, 0x01, [
        si(dt, distinct=True),
        _attr_nonresident(0x80, _runlist(8, MFT_CLUSTER), 8 * CLUSTER, 7,
                          8 * CLUSTER),
    ])

    # rec 5: root directory
    records[5] = make_record(5, 5, 0x03, [
        si(dt, distinct=True),
        fn(5, ".", 0, True, dt),
        _attr_resident(0x90, b"\x00" * 16, name="$I30"),  # minimal $INDEX_ROOT
    ])

    # entry 24: allocated file, resident data, with an alternate data stream
    zone = b"[ZoneTransfer]\r\nZoneId=3\r\n"
    records[24] = make_record(24, 1, 0x01, [
        si(now, distinct=True),
        fn(5, "hello.txt", len(hello), False, now),
        _attr_resident(0x80, hello),
        _attr_resident(0x80, zone, attr_id=3, name="Zone.Identifier"),
    ])

    # entry 25: DELETED file, non-resident data at cluster 20
    del_lcn = 20
    img[del_lcn * CLUSTER: del_lcn * CLUSTER + len(secret)] = secret
    last_vcn = (len(secret) + CLUSTER - 1) // CLUSTER - 1
    records[25] = make_record(25, 2, 0x00, [
        si(dt, distinct=True),
        fn(5, "secret.txt", len(secret), False, dt),
        _attr_nonresident(0x80, _runlist(last_vcn + 1, del_lcn), len(secret),
                          last_vcn, (last_vcn + 1) * CLUSTER),
    ])

    # entry 26: subdirectory "logs"
    records[26] = make_record(26, 1, 0x03, [
        si(dt, distinct=True),
        fn(5, "logs", 0, True, dt),
        _attr_resident(0x90, b"\x00" * 16, name="$I30"),
    ])

    # entry 27: file inside "logs", TIMESTOMPED
    #   $SI: all four stamps identical and earlier than $FN creation
    stomp_si = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    stomp_fn = datetime(2024, 5, 20, 8, 0, 0, tzinfo=timezone.utc)
    applog = b"2024-05-20 08:00:01 app started\n" * 5
    records[27] = make_record(27, 1, 0x01, [
        si(stomp_si),
        fn(26, "app.log", len(applog), False, stomp_fn),
        _attr_resident(0x80, applog),
    ])

    mft_base = MFT_CLUSTER * CLUSTER
    for num, rec in records.items():
        img[mft_base + num * REC: mft_base + num * REC + REC] = rec

    meta = {
        "hello.txt": hello,
        "secret.txt": secret,
        "app.log": applog,
        "zone": zone,
        "stomp_si": stomp_si,
        "stomp_fn": stomp_fn,
    }
    return bytes(img), meta


def make_usn_v2(usn: int, name: str, file_entry: int, parent_entry: int,
                reason: int, when: datetime, attrs: int = 0x20) -> bytes:
    name_b = name.encode("utf-16-le")
    name_off = 0x3C
    length = name_off + len(name_b)
    length = (length + 7) & ~7
    b = bytearray(length)
    struct.pack_into("<IHH", b, 0, length, 2, 0)
    struct.pack_into("<Q", b, 8, file_entry | (1 << 48))
    struct.pack_into("<Q", b, 16, parent_entry | (1 << 48))
    struct.pack_into("<Q", b, 24, usn)
    struct.pack_into("<Q", b, 32, ft(when))
    struct.pack_into("<IIII", b, 40, reason, 0, 0, attrs)
    struct.pack_into("<HH", b, 56, len(name_b), name_off)
    b[name_off:name_off + len(name_b)] = name_b
    return bytes(b)


def build_usn_journal() -> tuple[bytes, list]:
    from datetime import timedelta
    base = datetime(2024, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        make_usn_v2(0x100, "notes.txt", 40, 5, 0x00000100, base),                 # FILE_CREATE
        make_usn_v2(0x180, "notes.txt", 40, 5, 0x00000002 | 0x80000000,
                    base + timedelta(minutes=1)),                                 # DATA_EXTEND|CLOSE
        make_usn_v2(0x200, "evil.exe", 41, 5, 0x00000100,
                    base + timedelta(minutes=5)),
        make_usn_v2(0x280, "evil.exe", 41, 5, 0x00000200 | 0x80000000,
                    base + timedelta(minutes=6)),                                 # FILE_DELETE|CLOSE
    ]
    # sparse gap then a record, to exercise the NUL-run skipper
    blob = recs[0] + recs[1] + b"\x00" * 512 + recs[2] + recs[3]
    return blob, recs


def raw_mft_only() -> tuple[bytes, dict]:
    """Just the $MFT region of the image, as a bare extracted $MFT file."""
    img, meta = build_ntfs_image()
    start = MFT_CLUSTER * CLUSTER
    return img[start:start + 8 * CLUSTER], meta
