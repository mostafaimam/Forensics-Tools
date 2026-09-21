"""Build a real (unencrypted) iOS-backup-shaped folder for tests."""

from __future__ import annotations

import hashlib
import plistlib
import sqlite3
from datetime import datetime, timezone

# plistlib's binary writer wants naive datetimes (it treats them as UTC,
# matching Apple's convention) unless aware_datetime=True is passed - use
# naive throughout so the fixtures work the same across Python versions.
from pathlib import Path

_COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def file_id(domain: str, relative_path: str) -> str:
    return hashlib.sha1(f"{domain}-{relative_path}".encode()).hexdigest()


def plain_file_blob(*, size=1234, mode=0o100644, uid=501, gid=501,
                    protection_class=3, birth=None, last_modified=None) -> bytes:
    """A plain (non-keyed-archive) plist - plists.load() returns it as-is,
    exercising the same code path fileentry.decode() uses for a real
    (keyed-archive) blob without needing to forge that wrapping."""
    d = {
        "Size": size, "Mode": mode, "UserID": uid, "GroupID": gid,
        "ProtectionClass": protection_class,
        "Birth": birth or datetime(2025, 1, 1),
        "LastModified": last_modified or datetime(2025, 6, 1),
        "LastStatusChange": datetime(2025, 6, 1),
    }
    return plistlib.dumps(d, fmt=plistlib.FMT_BINARY)


def keyed_archive_file_blob(*, size=999, mode=0o100644) -> bytes:
    """A genuine minimal NSKeyedArchiver-wrapped dict, to exercise the
    is_keyed_archive()/unwrap() integration end to end."""
    objects = [
        "$null",                                            # 0
        {"$class": plistlib.UID(2), "NS.keys": [plistlib.UID(3),
         plistlib.UID(4)], "NS.objects": [plistlib.UID(5), plistlib.UID(6)]},
        {"$classes": ["NSDictionary", "NSObject"],
         "$classname": "NSDictionary"},                      # 2
        "Size",                                              # 3
        "Mode",                                              # 4
        size,                                                # 5
        mode,                                                # 6
    ]
    archive = {"$archiver": "NSKeyedArchiver", "$version": 100000,
              "$top": {"root": plistlib.UID(1)}, "$objects": objects}
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


def build_backup(root: Path, *, is_encrypted=False, files=None) -> Path:
    backup = root / "00008030-001A2D3E1234567X"
    backup.mkdir(parents=True)

    manifest = {"IsEncrypted": is_encrypted, "Date": datetime.now()}
    (backup / "Manifest.plist").write_bytes(
        plistlib.dumps(manifest, fmt=plistlib.FMT_BINARY))

    info = {
        "Device Name": "Test iPhone", "Product Type": "iPhone14,5",
        "Product Version": "17.4", "Serial Number": "F2LXXXX0XXX",
        "Unique Identifier": "00008030-001A2D3E1234567X",
    }
    (backup / "Info.plist").write_bytes(
        plistlib.dumps(info, fmt=plistlib.FMT_BINARY))

    con = sqlite3.connect(backup / "Manifest.db")
    con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, "
               "relativePath TEXT, flags INTEGER, file BLOB)")

    if files is None and not is_encrypted:
        files = [
            ("HomeDomain", "Library/SMS/sms.db", plain_file_blob(size=40960),
             True),
            ("CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.JPG",
             plain_file_blob(size=2_500_000, mode=0o100644), True),
            ("HomeDomain", "Library/Preferences/missing.plist",
             plain_file_blob(size=10), False),
        ]
    for domain, rel_path, blob, on_disk in (files or []):
        fid = file_id(domain, rel_path)
        con.execute("INSERT INTO Files VALUES (?, ?, ?, 1, ?)",
                   (fid, domain, rel_path, blob))
        if on_disk:
            sub = backup / fid[:2]
            sub.mkdir(exist_ok=True)
            (sub / fid).write_bytes(b"synthetic file content")
    con.commit()
    con.close()
    return backup


def build_encrypted_backup(root: Path) -> Path:
    return build_backup(root, is_encrypted=True, files=[])
