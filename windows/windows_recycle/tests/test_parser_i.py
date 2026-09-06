from datetime import datetime, timezone

from _helpers import make_i_v1, make_i_v2
from windows_recycle.parser_i import parse_i_bytes, parse_i_file


def test_v2_roundtrip():
    dt = datetime(2021, 6, 15, 13, 45, 30, tzinfo=timezone.utc)
    data = make_i_v2(r"C:\Users\alice\Documents\secret.docx", 4096, dt)
    rec = parse_i_bytes(data)
    assert rec.format_version == "2"
    assert rec.original_path == r"C:\Users\alice\Documents\secret.docx"
    assert rec.original_size == 4096
    assert rec.deleted_utc == dt
    assert rec.drive == "C:"
    assert not rec.parse_error


def test_v1_roundtrip():
    dt = datetime(2016, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    data = make_i_v1(r"D:\stuff\a.txt", 10, dt)
    rec = parse_i_bytes(data)
    assert rec.format_version == "1"
    assert rec.original_path == r"D:\stuff\a.txt"
    assert rec.deleted_utc == dt
    assert rec.drive == "D:"


def test_unicode_path():
    dt = datetime(2022, 3, 3, tzinfo=timezone.utc)
    p = r"C:\Users\Ola\Downloads\rapport-æøå-документ.pdf"
    rec = parse_i_bytes(make_i_v2(p, 1, dt))
    assert rec.original_path == p


def test_truncated_header():
    rec = parse_i_bytes(b"\x02\x00\x00")
    assert rec.parse_error
    assert "too small" in rec.parse_error


def test_zero_filetime_is_blank():
    data = make_i_v2(r"C:\x", 0, datetime(1601, 1, 1, tzinfo=timezone.utc))
    rec = parse_i_bytes(data)
    assert rec.deleted_utc is None
    assert rec.deleted_utc_iso == ""


def test_unknown_version():
    import struct
    rec = parse_i_bytes(struct.pack("<QQQ", 99, 0, 0) + b"\x00" * 8)
    assert "unknown $I version 99" in rec.parse_error


def test_v2_truncated_path_field_warns():
    import struct
    dt = datetime(2020, 1, 1, tzinfo=timezone.utc)
    good = make_i_v2(r"C:\long\path\file.bin", 5, dt)
    rec = parse_i_bytes(good[:-6])  # chop the tail off the path
    assert rec.warnings
    assert rec.original_path.startswith(r"C:\long\path\file")


def test_recycle_id_and_content_match(tmp_path):
    dt = datetime(2023, 9, 1, tzinfo=timezone.utc)
    (tmp_path / "$IAB12CD.txt").write_bytes(make_i_v2(r"C:\a\b.txt", 3, dt))
    (tmp_path / "$RAB12CD.txt").write_bytes(b"hello")
    rec = parse_i_file(tmp_path / "$IAB12CD.txt")
    assert rec.recycle_id == "AB12CD.txt"
