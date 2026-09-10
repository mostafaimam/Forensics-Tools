"""Build synthetic .fseventsd gzip logs for the macos_fsevents test-suite."""

from __future__ import annotations

import gzip
import struct
from pathlib import Path

CREATED = 0x00400000
REMOVED = 0x00800000
RENAMED = 0x02000000
MODIFIED = 0x04000000
FOLDER_CREATED = 0x20000000
FILE_EVENT = 0x00008000
MOUNT = 0x00000002


def _record(path: str, eid: int, flags: int, node: int, version: int) -> bytes:
    b = path.encode("utf-8") + b"\x00"
    if version == 1:
        b += struct.pack("<QI", eid, flags)
    else:
        b += struct.pack("<QIQ", eid, flags, node)
    return b


def build_log(records, version: int = 2, magic: bytes | None = None) -> bytes:
    magic = magic or {1: b"1SLD", 2: b"2SLD", 3: b"3SLD"}[version]
    body = b"".join(_record(*r, version) for r in records)
    page = magic + struct.pack("<II", 0, 12 + len(body)) + body
    return gzip.compress(page)


def build_volume(root: Path) -> Path:
    d = root / ".fseventsd"
    d.mkdir(parents=True)
    (d / "fseventsd-uuid").write_text("11111111-2222-3333-4444-555555555555")

    log1 = [
        ("Users/victim/Documents/report.pages", 1001,
         CREATED | FILE_EVENT, 501),
        ("Users/victim/Documents/report.pages", 1002, MODIFIED | FILE_EVENT,
         501),
        ("Users/victim/Downloads/Installer.dmg", 1003, CREATED | FILE_EVENT,
         502),
        ("private/tmp/.x", 1004, FOLDER_CREATED, 900),
        ("private/tmp/.x/payload", 1005, CREATED | FILE_EVENT, 901),
    ]
    build = build_log(log1, version=2)
    (d / "0000000000000fa0").write_bytes(build)

    log2 = [
        ("private/tmp/.x/payload", 2001, REMOVED | FILE_EVENT, 901),
        ("private/tmp/.x", 2002, REMOVED, 900),
        ("Users/victim/.zsh_history", 2003, REMOVED | FILE_EVENT, 77),
        ("Library/Application Support/com.apple.TCC/TCC.db", 2004,
         RENAMED | FILE_EVENT, 88),
        ("Volumes/USB", 2005, MOUNT, 0),
    ]
    (d / "0000000000001388").write_bytes(build_log(log2, version=2))

    # a v1 (DLS1) log with no node ids
    log3 = [
        ("Applications/Xcode.app/Contents/Info.plist", 3001, MODIFIED, 0),
    ]
    (d / "0000000000001770").write_bytes(build_log(log3, version=1))
    return root
