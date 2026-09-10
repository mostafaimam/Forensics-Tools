"""Heuristic flags for a Bluetooth device record."""

from __future__ import annotations

import re

_GENERIC = re.compile(r"^(keyboard|mouse|trackpad|headset|headphones|speaker|"
                      r"device|bluetooth (keyboard|mouse)|hc-0[56]|"
                      r"ble[ _-]?device|unknown|iphone|ipad)$", re.I)


def flag(dev) -> list[str]:
    out: list[str] = []

    if dev.is_paired and (dev.is_hid or dev.device_type == "peripheral"):
        kind = dev.device_minor or "input device"
        out.append(f"paired input device ({kind}) - a keystroke-injection "
                   f"vector")
    elif dev.is_hid and not dev.is_paired:
        out.append("input device seen but not paired")

    if dev.is_paired and dev.device_type == "audio/video" and \
            dev.device_minor in ("microphone", "headset", "hands-free"):
        out.append(f"paired audio-input device ({dev.device_minor}) - "
                   f"possible covert microphone")

    if dev.name and _GENERIC.match(dev.name.strip()):
        out.append(f"device has a generic / default name ('{dev.name}')")
    if not dev.name and (dev.is_paired or dev.is_hid):
        out.append("paired / HID device with no name recorded")

    if dev.manufacturer.startswith("company 0x") and dev.is_paired:
        out.append(f"paired device from an unrecognised manufacturer "
                   f"({dev.manufacturer})")

    if not dev.is_paired and dev.last_inquiry_update and \
            not dev.last_services_update and not dev.name:
        out.append("device seen once by inquiry, never named or paired")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "paired input device (": "high",
    "input device seen but not paired": "medium",
    "paired audio-input device (": "medium",
    "device has a generic / default name": "low",
    "paired / HID device with no name recorded": "medium",
    "paired device from an unrecognised manufacturer": "low",
    "device seen once by inquiry": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
