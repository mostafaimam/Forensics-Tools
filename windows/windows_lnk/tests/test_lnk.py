import uuid
from datetime import datetime, timezone

import pytest

from _synth import build_lnk
from windows_lnk.lnk import LnkError, parse


def test_header_fields():
    data = build_lnk(
        created=datetime(2024, 3, 1, 9, 0, tzinfo=timezone.utc),
        written=datetime(2024, 3, 4, 15, 30, tzinfo=timezone.utc),
        size=45678)
    lnk = parse(data, "report.lnk")
    assert lnk.target_created.year == 2024 and lnk.target_created.hour == 9
    assert lnk.target_modified == datetime(2024, 3, 4, 15, 30, tzinfo=timezone.utc)
    assert lnk.target_size == 45678
    assert "ARCHIVE" in lnk.file_attributes
    assert lnk.show_command == "Normal"
    assert "IsUnicode" in lnk.flag_names


def test_link_info_and_strings():
    lnk = parse(build_lnk(target=r"C:\Users\a\Documents\report.docx",
                          serial=0x1A2B3C4D, label="OS-DISK",
                          args="/quiet", working=r"C:\Users\a\Documents"))
    assert lnk.local_base_path == r"C:\Users\a\Documents\report.docx"
    assert lnk.target_path == r"C:\Users\a\Documents\report.docx"
    assert lnk.drive_type == "Fixed"
    assert lnk.drive_serial == "1A2B3C4D"
    assert lnk.volume_label == "OS-DISK"
    assert lnk.arguments == "/quiet"
    assert lnk.working_dir == r"C:\Users\a\Documents"
    assert lnk.name == "A report shortcut"
    assert lnk.relative_path == r"..\report.docx"


def test_tracker_machine_id_and_mac():
    obj = uuid.uuid1(node=0x8CC6815BA594)         # embed a known MAC
    lnk = parse(build_lnk(machine="FORENSIC-PC", obj_uuid=obj))
    assert lnk.tracker is not None
    assert lnk.tracker.machine_id == "FORENSIC-PC"
    assert lnk.tracker.object_mac_address == "8c:c6:81:5b:a5:94"
    assert lnk.tracker.object_created_utc is not None
    assert lnk.tracker.droid_object.lower() == str(obj)


def test_not_a_lnk():
    with pytest.raises(LnkError):
        parse(b"MZ\x90\x00" + b"\x00" * 100)
    with pytest.raises(LnkError):
        parse(b"\x4c\x00\x00\x00" + b"\x11" * 16 + b"\x00" * 60)


def test_too_small():
    with pytest.raises(LnkError):
        parse(b"\x4c\x00")
