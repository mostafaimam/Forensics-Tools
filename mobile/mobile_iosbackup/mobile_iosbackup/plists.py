"""Load a plist, transparently unwrapping it if it's an NSKeyedArchiver."""

from __future__ import annotations

import plistlib

from mobile_iosbackup.nskeyedarchiver import is_keyed_archive, unwrap


def load(data: bytes):
    obj = plistlib.loads(data)
    if is_keyed_archive(obj):
        return unwrap(obj)
    return obj


def load_file(path):
    with open(path, "rb") as fh:
        return load(fh.read())
