r"""Parse the ``LinkTargetIDList`` - a sequence of shell ``ItemID`` structures.

Only the forensically useful *file-entry* items (class indicator ``0x31`` /
``0x32``) are decoded in detail, including the ``BEEF0004`` extension block
which carries the long file name, the file's created / accessed times, and -
on Windows 7 and later - the target's ``$MFT`` entry and sequence number.

Note: the timestamps in shell items are DOS date/time - **local time, no
timezone** - so they are emitted without a ``Z`` suffix.
"""

from __future__ import annotations

import struct
from datetime import datetime

SIG_BEEF0004 = 0xBEEF0004


def dos_datetime(date: int, time: int) -> str:
    if date == 0:
        return ""
    day = date & 0x1F
    month = (date >> 5) & 0x0F
    year = 1980 + (date >> 9)
    sec = (time & 0x1F) * 2
    minute = (time >> 5) & 0x3F
    hour = (time >> 11) & 0x1F
    try:
        return datetime(year, month, day, hour, minute, sec).strftime(
            "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return ""


def parse_idlist(data: bytes) -> list[dict]:
    items: list[dict] = []
    pos = 0
    n = len(data)
    while pos + 2 <= n:
        size = struct.unpack_from("<H", data, pos)[0]
        if size == 0:
            break
        if size < 2 or pos + size > n:
            break
        items.append(_parse_item(data[pos + 2:pos + size]))
        pos += size
    return items


def _parse_item(body: bytes) -> dict:
    if not body:
        return {"type": "empty"}
    indicator = body[0]
    item: dict = {"type": f"0x{indicator:02x}", "raw_size": len(body) + 2}

    if indicator in (0x1F,):
        item["type"] = "root/GUID"
        return item
    if indicator & 0x70 == 0x30:                # file / directory entry
        item["type"] = "directory" if indicator & 0x01 else "file"
        _parse_file_entry(body, item)
        return item
    if indicator in (0x2E, 0x2F):
        item["type"] = "drive"
        item["name"] = body[1:4].decode("latin-1", "replace")
        return item
    return item


def _parse_file_entry(body: bytes, item: dict) -> None:
    try:
        file_size = struct.unpack_from("<I", body, 2)[0]
        mdate, mtime = struct.unpack_from("<HH", body, 6)
        attrs = struct.unpack_from("<H", body, 10)[0]
    except struct.error:
        return
    item["file_size"] = file_size
    item["modified"] = dos_datetime(mdate, mtime)
    item["attributes"] = attrs

    # primary (short) name: ANSI, NUL-terminated, from offset 12
    end = body.find(b"\x00", 12)
    if end < 0:
        end = len(body)
    item["name"] = body[12:end].decode("latin-1", "replace")
    ext_pos = end + 1
    if (ext_pos - 12) % 2:                       # pad to WORD boundary
        ext_pos += 1

    while ext_pos + 8 <= len(body):
        ext_size = struct.unpack_from("<H", body, ext_pos)[0]
        if ext_size < 8 or ext_pos + ext_size > len(body):
            break
        version = struct.unpack_from("<H", body, ext_pos + 2)[0]
        sig = struct.unpack_from("<I", body, ext_pos + 4)[0]
        if sig == SIG_BEEF0004:
            _parse_beef0004(body[ext_pos:ext_pos + ext_size], version, item)
        ext_pos += ext_size


def _parse_beef0004(blk: bytes, version: int, item: dict) -> None:
    try:
        cdate, ctime = struct.unpack_from("<HH", blk, 8)
        adate, atime = struct.unpack_from("<HH", blk, 12)
    except struct.error:
        return
    item["created"] = dos_datetime(cdate, ctime)
    item["accessed"] = dos_datetime(adate, atime)

    off = 18
    if version >= 0x07:
        # unknown(2), FileReference u64 (48-bit entry | 16-bit seq), unknown(8)
        try:
            ref = struct.unpack_from("<Q", blk, off + 2)[0]
            entry = ref & 0x0000FFFFFFFFFFFF
            seq = ref >> 48
            if entry:
                item["mft_entry"] = entry
                item["mft_sequence"] = seq
        except struct.error:
            pass
        off += 2 + 8 + 8
        off += 4                                  # long string size (v8+) / unk
    elif version >= 0x03:
        off = 18

    # long name: UTF-16LE, NUL-terminated
    if 0 <= off < len(blk):
        end = blk.find(b"\x00\x00", off)
        if end < 0 or (end - off) % 2:
            end = len(blk) - (len(blk) % 2)
        name = blk[off:end].decode("utf-16-le", "replace").split("\x00")[0]
        if name:
            item["long_name"] = name
