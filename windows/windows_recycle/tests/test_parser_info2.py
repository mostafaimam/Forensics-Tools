from datetime import datetime, timezone

from _helpers import make_info2, make_info2_record
from windows_recycle.parser_info2 import parse_info2_bytes


def test_basic_records():
    d1 = datetime(2004, 5, 1, 8, 0, 0, tzinfo=timezone.utc)
    d2 = datetime(2005, 12, 25, 22, 30, 0, tzinfo=timezone.utc)
    data = make_info2([
        make_info2_record(r"C:\Documents and Settings\bob\a.doc", 0, 2, 8192, d1),
        make_info2_record(r"D:\media\clip.avi", 1, 3, 1048576, d2),
    ])
    recs = parse_info2_bytes(data)
    assert len(recs) == 2
    assert recs[0].original_path == r"C:\Documents and Settings\bob\a.doc"
    assert recs[0].drive == "C:"
    assert recs[0].index == 0
    assert recs[0].deleted_utc == d1
    assert recs[1].original_size == 1048576
    assert recs[1].drive == "D:"
    assert all(r.active for r in recs)
    assert all(not r.parse_error for r in recs)


def test_inactive_slot_flagged():
    d = datetime(2004, 1, 1, tzinfo=timezone.utc)
    data = make_info2([
        make_info2_record(r"C:\x\removed.txt", 5, 2, 1, d, active=False),
    ])
    rec = parse_info2_bytes(data)[0]
    assert rec.active is False
    # unicode name still recovers the path
    assert rec.original_path == r"C:\x\removed.txt"


def test_trailing_bytes_reported():
    d = datetime(2004, 1, 1, tzinfo=timezone.utc)
    data = make_info2([make_info2_record(r"C:\a", 0, 2, 1, d)]) + b"\x01\x02\x03"
    recs = parse_info2_bytes(data)
    assert any(r.parse_error and "trailing bytes" in r.parse_error for r in recs)


def test_header_only_is_empty():
    recs = parse_info2_bytes(b"\x05\x00\x00\x00" + b"\x00" * 12)
    assert len(recs) == 1
    assert recs[0].parse_error == "no records found"


def test_too_small():
    recs = parse_info2_bytes(b"\x05\x00")
    assert recs[0].parse_error and "too small" in recs[0].parse_error
