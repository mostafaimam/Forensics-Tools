import struct

from windows_lnk.shellitems import dos_datetime, parse_idlist


def _file_item(short_name: str, long_name: str, mft_entry: int, mft_seq: int) -> bytes:
    # base file-entry item: indicator 0x32, filesize, dos mtime, attrs, short name
    body = bytes([0x32, 0x00])
    body += struct.pack("<I", 1234)               # file size
    body += struct.pack("<HH", 0, 0)              # dos modified
    body += struct.pack("<H", 0x20)               # attrs
    sn = short_name.encode("latin-1") + b"\x00"
    body += sn
    if (len(body) - 12) % 2:
        body += b"\x00"
    # BEEF0004 v9 extension: size, ver, sig, ctime, atime, id, unk2, fileref(8),
    #                        unk8, longstrsize(4), long name (UTF-16LE) + NUL
    ln = long_name.encode("utf-16-le") + b"\x00\x00"
    ref = mft_entry | (mft_seq << 48)
    ext = struct.pack("<HHI", 0, 9, 0xBEEF0004)
    ext += struct.pack("<HH", 0, 0)               # created dos
    ext += struct.pack("<HH", 0, 0)               # accessed dos
    ext += struct.pack("<H", 0x14)                # identifier
    ext += struct.pack("<H", 0)                   # unknown (2)
    ext += struct.pack("<Q", ref)                 # file reference
    ext += struct.pack("<Q", 0)                   # unknown (8)
    ext += struct.pack("<I", len(ln))             # long string size
    ext += ln
    ext = struct.pack("<H", len(ext)) + ext[2:]
    body += ext
    return struct.pack("<H", len(body) + 2) + body


def test_dos_datetime():
    # 2024-06-01 09:30:00 -> date/time words
    date = ((2024 - 1980) << 9) | (6 << 5) | 1
    time = (9 << 11) | (30 << 5) | 0
    assert dos_datetime(date, time) == "2024-06-01T09:30:00"
    assert dos_datetime(0, 0) == ""


def test_file_entry_with_beef0004():
    idlist = _file_item("REPORT~1.DOC", "report of findings.docx", 51234, 7) \
        + b"\x00\x00"
    items = parse_idlist(idlist)
    assert len(items) == 1
    it = items[0]
    assert it["type"] == "file"
    assert it["name"] == "REPORT~1.DOC"
    assert it["long_name"] == "report of findings.docx"
    assert it["mft_entry"] == 51234
    assert it["mft_sequence"] == 7


def test_empty_idlist():
    assert parse_idlist(b"\x00\x00") == []
