"""Synthetic macOS install artefacts for the test-suite."""

from __future__ import annotations

import datetime as dt
import plistlib
from pathlib import Path

_UTC = dt.timezone.utc


def build_volume(root: Path) -> Path:
    hist = [
        {"date": dt.datetime(2026, 1, 5, 8, 0, tzinfo=_UTC),
         "displayName": "macOS 14.3", "displayVersion": "14.3",
         "packageIdentifiers": ["com.apple.pkg.macOSBrain"],
         "processName": "softwareupdated", "contentType": "software"},
        {"date": dt.datetime(2026, 1, 6, 9, 0, tzinfo=_UTC),
         "displayName": "XProtectPlistConfigData",
         "displayVersion": "2185",
         "packageIdentifiers": ["com.apple.pkg.XProtectPlistConfigData"],
         "processName": "softwareupdated", "contentType": "config-data"},
        {"date": dt.datetime(2026, 2, 10, 14, 0, tzinfo=_UTC),
         "displayName": "Google Chrome", "displayVersion": "133.0",
         "packageIdentifiers": ["com.google.Chrome"],
         "processName": "installer", "contentType": "software"},
        {"date": dt.datetime(2026, 3, 1, 22, 0, tzinfo=_UTC),
         "displayName": "SupportHelper", "displayVersion": "1.0",
         "packageIdentifiers": ["com.acme.support.helper"],
         "processName": "bash", "contentType": "software"},
        {"date": dt.datetime(2026, 3, 2, 3, 0, tzinfo=_UTC),
         "displayName": "Corp Profile", "displayVersion": "",
         "packageIdentifiers": ["com.corp.mdm.profile"],
         "processName": "installer", "contentType": "config-profile"},
    ]
    p = root / "Library/Receipts/InstallHistory.plist"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(plistlib.dumps(hist))

    receipts = {
        "com.apple.pkg.macOSBrain": {
            "PackageIdentifier": "com.apple.pkg.macOSBrain",
            "PackageVersion": "14.3", "InstallPrefixPath": "/",
            "InstallProcessName": "installer",
            "InstallDate": dt.datetime(2026, 1, 5, 8, 5, tzinfo=_UTC),
            "PackageFileName": "macOSBrain.pkg"},
        "com.google.Chrome": {
            "PackageIdentifier": "com.google.Chrome",
            "PackageVersion": "133.0", "InstallPrefixPath": "/",
            "InstallProcessName": "installer",
            "InstallDate": dt.datetime(2026, 2, 10, 14, 1, tzinfo=_UTC),
            "PackageFileName": "GoogleChrome.pkg"},
        "com.evil.dropper": {
            "PackageIdentifier": "com.evil.dropper",
            "PackageVersion": "0.1",
            "InstallPrefixPath": "/Users/victim",
            "InstallProcessName": "installer",
            "InstallDate": dt.datetime(2026, 3, 3, 1, 0, tzinfo=_UTC),
            "PackageFileName": "/Users/victim/Downloads/Update.pkg"},
    }
    rd = root / "private/var/db/receipts"
    rd.mkdir(parents=True, exist_ok=True)
    for pid, d in receipts.items():
        (rd / f"{pid}.plist").write_bytes(plistlib.dumps(d))
        (rd / f"{pid}.bom").write_bytes(b"BOMStore")
    return root
