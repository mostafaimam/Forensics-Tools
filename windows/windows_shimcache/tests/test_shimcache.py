from datetime import datetime, timezone

import pytest

from _synth import (
    system_hive_with_shimcache,
    win7_blob,
    win10_blob,
)
from windows_shimcache.extract import from_hive_bytes
from windows_shimcache.shimcache import ShimCacheError, detect_format, parse

D1 = datetime(2024, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
D2 = datetime(2024, 2, 15, 8, 30, 0, tzinfo=timezone.utc)


def test_detect_and_parse_win10():
    blob = win10_blob([
        (r"C:\Windows\System32\cmd.exe", D1),
        (r"C:\Users\a\AppData\Local\Temp\evil.exe", D2),
    ])
    assert detect_format(blob) == "windows-10"
    entries = parse(blob)
    assert [e.path for e in entries] == [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Users\a\AppData\Local\Temp\evil.exe",
    ]
    assert entries[0].position == 0
    assert entries[0].last_modified == D1
    assert entries[1].last_modified == D2
    assert entries[0].executed is None


def test_detect_and_parse_win7_with_executed_flag():
    blob = win7_blob([
        (r"C:\Windows\explorer.exe", D1, True),
        (r"C:\temp\dropper.exe", D2, False),
    ])
    assert detect_format(blob) == "windows-7"
    entries = parse(blob)
    assert entries[0].path == r"C:\Windows\explorer.exe"
    assert entries[0].executed is True
    assert entries[1].executed is False
    assert entries[1].last_modified == D2


def test_from_system_hive():
    blob = win10_blob([(r"C:\a\b.exe", D1)])
    hive = system_hive_with_shimcache(blob)
    entries = from_hive_bytes(hive)
    assert len(entries) == 1
    assert entries[0].path == r"C:\a\b.exe"
    assert entries[0].control_set == "ControlSet001"


def test_bad_signature():
    with pytest.raises(ShimCacheError):
        parse(b"\x11\x22\x33\x44" + b"\x00" * 100)


def test_truncated_entry_is_tolerated():
    blob = win10_blob([(r"C:\x.exe", D1)])
    entries = parse(blob[:-4])          # chop the data_size field
    assert len(entries) <= 1
