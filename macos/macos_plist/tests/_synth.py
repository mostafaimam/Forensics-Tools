"""Build test plists (real bplist/XML via plistlib, plus a hand-made keyed
archive)."""

from __future__ import annotations

import plistlib
from datetime import datetime, timezone

try:
    from plistlib import UID
except ImportError:  # pragma: no cover
    UID = None


def bplist(obj) -> bytes:
    return plistlib.dumps(obj, fmt=plistlib.FMT_BINARY, aware_datetime=True)


def xmlplist(obj) -> bytes:
    return plistlib.dumps(obj, fmt=plistlib.FMT_XML, aware_datetime=True)


def sample_prefs() -> dict:
    return {
        "AppleLanguages": ["en-GB", "fr"],
        "com.apple.something": {"Enabled": True, "Count": 3},
        "LastRun": datetime(2024, 6, 1, 9, 30, tzinfo=timezone.utc),
        "Token": b"\x01\x02\x03\x04",
    }


def keyed_archive_dock() -> bytes:
    """A minimal NSKeyedArchiver: root -> NSDictionary {name: "Safari",
    added: NSDate}."""
    objects = [
        "$null",                                              # 0
        {"$class": UID(6), "NS.keys": [UID(2), UID(3)],       # 1  root dict
         "NS.objects": [UID(4), UID(5)]},
        "name",                                               # 2
        "added",                                              # 3
        "Safari",                                             # 4
        {"$class": UID(7), "NS.time": 707313600.0},           # 5  NSDate
        {"$classname": "NSDictionary",                        # 6
         "$classes": ["NSDictionary", "NSObject"]},
        {"$classname": "NSDate", "$classes": ["NSDate", "NSObject"]},  # 7
    ]
    archive = {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$objects": objects,
        "$top": {"root": UID(1)},
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY, aware_datetime=True)
