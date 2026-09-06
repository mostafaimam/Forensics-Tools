"""Hand-build .lnk files for the test-suite."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_GREG = datetime(1582, 10, 15, tzinfo=timezone.utc)
CLSID = uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le

F_TARGET_IDLIST = 0x1
F_LINK_INFO = 0x2
F_NAME = 0x4
F_RELATIVE = 0x8
F_WORKING_DIR = 0x10
F_ARGUMENTS = 0x20


def ft(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc) - _FT_EPOCH).total_seconds()
               * 1e7)


def _dos(dt: datetime) -> tuple[int, int]:
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date, time


def _header(flags: int, created: datetime, accessed: datetime,
            written: datetime, size: int) -> bytes:
    b = bytearray(0x4C)
    struct.pack_into("<I", b, 0, 0x4C)
    b[4:20] = CLSID
    struct.pack_into("<I", b, 20, flags)
    struct.pack_into("<I", b, 24, 0x20)          # ARCHIVE
    struct.pack_into("<QQQ", b, 28, ft(created), ft(accessed), ft(written))
    struct.pack_into("<I", b, 52, size)
    struct.pack_into("<I", b, 60, 1)             # ShowNormal
    return bytes(b)


def _link_info(local_path: str, serial: int, label: str,
               drive_type: int = 3) -> bytes:
    lbp = local_path.encode("latin-1") + b"\x00"
    lbl = label.encode("latin-1") + b"\x00"
    header_size = 0x1C
    vol_off = header_size
    # VolumeID: size(4) drivetype(4) serial(4) labeloffset(4) label
    volume = struct.pack("<III", drive_type, serial, 0x10) + lbl
    volume = struct.pack("<I", len(volume) + 4) + volume
    lbp_off = vol_off + len(volume)
    cps_off = lbp_off + len(lbp)
    common_suffix = b"\x00"
    total = cps_off + len(common_suffix)
    out = struct.pack("<IIIIIII", total, header_size, 0x1,   # VolumeIDAndLocalBasePath
                      vol_off, lbp_off, 0, cps_off)
    out += volume + lbp + common_suffix
    return out


def _string_data(s: str) -> bytes:
    u = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + u


def _tracker(machine: str, obj_uuid: uuid.UUID) -> bytes:
    # TrackerDataBlock: size(4) sig(4) length(4) version(4) MachineID(16)
    #                   Droid{volume(16) object(16)} DroidBirth{volume(16) object(16)}
    vol = uuid.uuid4()
    body = machine.encode("latin-1")[:15].ljust(16, b"\x00")
    body += vol.bytes_le + obj_uuid.bytes_le
    body += vol.bytes_le + obj_uuid.bytes_le
    return struct.pack("<IIII", 16 + len(body), 0xA0000003, len(body) + 8, 0) + body


def build_lnk(*, target=r"C:\Users\a\Documents\report.docx",
              serial=0x1A2B3C4D, label="OS",
              machine="WORKSTATION-01",
              created=datetime(2024, 3, 1, 9, 0, tzinfo=timezone.utc),
              accessed=datetime(2024, 3, 5, 12, 0, tzinfo=timezone.utc),
              written=datetime(2024, 3, 4, 15, 30, tzinfo=timezone.utc),
              size=45678, args="/quiet", working=r"C:\Users\a\Documents",
              obj_uuid: uuid.UUID | None = None) -> bytes:
    obj_uuid = obj_uuid or uuid.uuid1()
    flags = F_LINK_INFO | F_NAME | F_RELATIVE | F_WORKING_DIR | F_ARGUMENTS | 0x80
    out = _header(flags, created, accessed, written, size)
    out += _link_info(target, serial, label)
    out += _string_data("A report shortcut")     # NAME
    out += _string_data(r"..\report.docx")       # RELATIVE_PATH
    out += _string_data(working)                  # WORKING_DIR
    out += _string_data(args)                     # ARGUMENTS
    out += _tracker(machine, obj_uuid)
    out += struct.pack("<I", 0)                   # terminal block
    return out
