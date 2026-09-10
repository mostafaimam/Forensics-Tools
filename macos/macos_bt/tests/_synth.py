"""Synthetic com.apple.Bluetooth.plist for the macos_bt test-suite."""

from __future__ import annotations

import datetime as dt
import plistlib
from pathlib import Path

_UTC = dt.timezone.utc


def _cod(major, minor=0, av=0):
    v = (major & 0x1F) << 8
    if major == 5:
        v |= (minor & 0x03) << 6
    if major == 4:
        v |= (av & 0x3F) << 2
    return v


def build(path: str) -> str:
    seen = dt.datetime(2026, 3, 13, 9, 0, tzinfo=_UTC)
    d = {
        "PairedDevices": ["aa-aa-aa-11-11-11", "bb-bb-bb-22-22-22",
                          "cc-cc-cc-33-33-33", "ee-ee-ee-55-55-55"],
        "HIDDevices": ["cc-cc-cc-33-33-33", "dd-dd-dd-44-44-44"],
        "DeviceCache": {
            "aa-aa-aa-11-11-11": {
                "Name": "Victim's iPhone", "Manufacturer": 0x004C,
                "ClassOfDevice": _cod(2),          # phone
                "LastNameUpdate": seen,
                "LastServicesUpdate": seen, "Services": ["1101", "111E"]},
            "bb-bb-bb-22-22-22": {
                "Name": "AirPods Pro", "Manufacturer": 0x004C,
                "ClassOfDevice": _cod(4, av=6),    # headphones
                "BatteryPercent": 85,
                "LastNameUpdate": seen, "LastServicesUpdate": seen,
                "Services": ["110B", "110E", "111E"]},
            "cc-cc-cc-33-33-33": {
                "Name": "Magic Keyboard", "Manufacturer": 0x004C,
                "VendorID": 0x05AC, "ProductID": 0x029C,
                "ClassOfDevice": _cod(5, minor=1),  # peripheral / keyboard
                "LastNameUpdate": seen.replace(hour=8),
                "LastServicesUpdate": seen.replace(hour=8)},
            "dd-dd-dd-44-44-44": {
                "Name": "HID Keyboard", "Manufacturer": 0x0131,
                "ClassOfDevice": _cod(5, minor=1),
                "LastInquiryUpdate": seen.replace(hour=2, minute=15)},
            "ee-ee-ee-55-55-55": {
                "Name": "BT Speaker", "Manufacturer": 0x0AFF,
                "ClassOfDevice": _cod(4, av=4),    # microphone
                "LastNameUpdate": seen.replace(day=12),
                "LastServicesUpdate": seen.replace(day=12)},
            "ff-ff-ff-66-66-66": {
                "Manufacturer": 0x0059,
                "ClassOfDevice": _cod(5),
                "LastInquiryUpdate": seen.replace(day=11)},
        },
    }
    Path(path).write_bytes(plistlib.dumps(d))
    return path
