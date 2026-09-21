"""Decode a Manifest.db Files.file BLOB into per-file metadata.

The blob is a binary plist - an NSKeyedArchiver-wrapped record in every
backup this project has been able to examine field names from public
write-ups, but Apple has never published this format, so field presence
is treated as best-effort: whatever of Birth / LastModified /
LastStatusChange / Size / Mode / UserID / GroupID / ProtectionClass is
present is used; nothing else is assumed.
"""

from __future__ import annotations

import stat as _stat
from dataclasses import dataclass
from datetime import datetime

from mobile_iosbackup.plists import load


@dataclass
class FileMeta:
    size: int | None
    mode: int | None
    file_type: str
    uid: int | None
    gid: int | None
    protection_class: int | None
    birth: str
    last_modified: str
    last_status_change: str


def _iso(v) -> str:
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%dT%H:%M:%SZ")
    return ""


def _type_for_mode(mode) -> str:
    if not isinstance(mode, int):
        return ""
    if _stat.S_ISREG(mode):
        return "file"
    if _stat.S_ISDIR(mode):
        return "directory"
    if _stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def decode(blob: bytes) -> FileMeta:
    try:
        obj = load(blob)
    except Exception:  # noqa: BLE001
        obj = None
    if not isinstance(obj, dict):
        return FileMeta(None, None, "", None, None, None, "", "", "")
    mode = obj.get("Mode")
    return FileMeta(
        size=obj.get("Size"),
        mode=mode,
        file_type=_type_for_mode(mode),
        uid=obj.get("UserID"),
        gid=obj.get("GroupID"),
        protection_class=obj.get("ProtectionClass"),
        birth=_iso(obj.get("Birth")),
        last_modified=_iso(obj.get("LastModified")),
        last_status_change=_iso(obj.get("LastStatusChange")),
    )
