"""Build synthetic .core_analytics files (plist form and NDJSON form)."""

from __future__ import annotations

import json
import plistlib
from datetime import datetime, timezone

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def mac_ts(dt: datetime) -> float:
    return (dt - _MAC_EPOCH).total_seconds()


def build_plist() -> bytes:
    doc = {
        "aggregates": [
            {
                "name": "com.apple.appLaunch",
                "timestamp": mac_ts(datetime(2026, 3, 16, 9, 0,
                                             tzinfo=timezone.utc)),
                "message": {
                    "bundleId": "com.apple.Safari",
                    "launches": 5,
                    "fg_time": 3600,
                },
            },
            {
                "name": "com.apple.appLaunch",
                "timestamp": mac_ts(datetime(2026, 3, 16, 14, 0,
                                             tzinfo=timezone.utc)),
                "message": {
                    "bundleId": "com.suspicious.tool",
                    "launches": 20,
                    "fg_time": 120,
                    "extra_flag": True,
                },
            },
        ]
    }
    return plistlib.dumps(doc, fmt=plistlib.FMT_BINARY)


def build_ndjson() -> bytes:
    lines = [
        json.dumps({
            "eventName": "com.apple.CoreDuet.appActivity",
            "time": mac_ts(datetime(2026, 3, 15, 8, 0,
                                    tzinfo=timezone.utc)),
            "payload": {"appId": "com.apple.Mail", "activations": 3,
                       "activeSeconds": 900},
        }),
        "",
        json.dumps({
            "eventName": "com.apple.something.unstructured",
            "date": mac_ts(datetime(2026, 3, 15, 9, 0,
                                    tzinfo=timezone.utc)),
        }),
    ]
    return ("\n".join(lines)).encode("utf-8")
