"""Parse com.apple.Bluetooth.plist."""

from __future__ import annotations

import datetime as _dt
import plistlib
from dataclasses import dataclass, field
from pathlib import Path

from macos_bt import flags as _flags

_MAC_EPOCH = _dt.datetime(2001, 1, 1, tzinfo=_dt.timezone.utc)

_COMPANIES = {
    0x004C: "Apple", 0x0006: "Microsoft", 0x00E0: "Google",
    0x0075: "Samsung", 0x0059: "Nordic Semiconductor", 0x000F: "Broadcom",
    0x0002: "Intel", 0x001D: "Qualcomm", 0x0157: "Anhui Huami (Amazfit)",
    0x0499: "Ruuvi", 0x05A7: "Sonos", 0x0087: "Garmin", 0x00D2: "Logitech",
    0x0131: "Cypress", 0x0822: "Adafruit", 0x0A12: "Cambridge Silicon",
}

_MAJOR = {1: "computer", 2: "phone", 3: "network", 4: "audio/video",
          5: "peripheral", 6: "imaging", 7: "wearable", 8: "toy", 9: "health"}
_PERIPHERAL_MINOR = {1: "keyboard", 2: "pointing device",
                     3: "keyboard + pointing"}


def _utc(v) -> str:
    if isinstance(v, _dt.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=_dt.timezone.utc)
        return v.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        f = float(v)
    except (TypeError, ValueError):
        return ""
    if f <= 0:
        return ""
    if f > 3_000_000_000:
        f -= _MAC_EPOCH.timestamp()
    try:
        return (_MAC_EPOCH + _dt.timedelta(seconds=f)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _device_type(cod) -> tuple[str, str]:
    try:
        c = int(cod)
    except (TypeError, ValueError):
        return "", ""
    major = _MAJOR.get((c >> 8) & 0x1F, "")
    minor = ""
    if major == "peripheral":
        minor = _PERIPHERAL_MINOR.get((c >> 6) & 0x03, "")
    elif major == "audio/video":
        av = (c >> 2) & 0x3F
        minor = {1: "headset", 2: "hands-free", 4: "microphone",
                 5: "loudspeaker", 6: "headphones", 8: "car audio"}.get(av, "")
    return major, minor


@dataclass
class Device:
    mac: str
    name: str
    is_paired: bool
    is_hid: bool
    device_type: str
    device_minor: str
    manufacturer: str
    vendor_id: str
    product_id: str
    class_of_device: str
    battery: str
    last_name_update: str
    last_inquiry_update: str
    last_services_update: str
    services: int
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "mac": self.mac, "name": self.name,
            "is_paired": "yes" if self.is_paired else "",
            "is_hid": "yes" if self.is_hid else "",
            "device_type": self.device_type,
            "device_minor": self.device_minor,
            "manufacturer": self.manufacturer, "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "class_of_device": self.class_of_device, "battery": self.battery,
            "last_name_update": self.last_name_update,
            "last_inquiry_update": self.last_inquiry_update,
            "last_services_update": self.last_services_update,
            "services": self.services, "source": self.source,
            "notable": ";".join(self.notable),
        }


def _norm_mac(m: str) -> str:
    return m.lower().replace(":", "-")


def parse(data: bytes, source: str) -> list[Device]:
    try:
        d = plistlib.loads(data)
    except Exception:                            # noqa: BLE001
        return []
    if not isinstance(d, dict):
        return []
    cache = d.get("DeviceCache") or {}
    paired = {_norm_mac(str(m)) for m in (d.get("PairedDevices") or [])}
    hid = {_norm_mac(str(m)) for m in (d.get("HIDDevices") or [])}

    out: list[Device] = []
    for mac, info in cache.items():
        if not isinstance(info, dict):
            continue
        nm = _norm_mac(str(mac))
        cod = info.get("ClassOfDevice")
        major, minor = _device_type(cod)
        man = info.get("Manufacturer")
        man_name = ""
        if isinstance(man, int):
            man_name = _COMPANIES.get(man, f"company 0x{man:04x}")
        elif man:
            man_name = str(man)
        dev = Device(
            mac=nm,
            name=str(info.get("Name", "") or info.get("defaultName", "")),
            is_paired=nm in paired, is_hid=nm in hid,
            device_type=major, device_minor=minor,
            manufacturer=man_name,
            vendor_id=(f"0x{info['VendorID']:04x}"
                       if isinstance(info.get("VendorID"), int) else ""),
            product_id=(f"0x{info['ProductID']:04x}"
                        if isinstance(info.get("ProductID"), int) else ""),
            class_of_device=(f"0x{int(cod):06x}" if isinstance(cod, int)
                             else str(cod or "")),
            battery=(f"{info['BatteryPercent']}" if "BatteryPercent" in info
                     else ""),
            last_name_update=_utc(info.get("LastNameUpdate")),
            last_inquiry_update=_utc(info.get("LastInquiryUpdate")),
            last_services_update=_utc(info.get("LastServicesUpdate")),
            services=len(info.get("Services") or []),
            source=source)
        dev.notable = _flags.flag(dev)
        out.append(dev)
    out.sort(key=lambda x: (not x.is_paired, x.last_inquiry_update
                            or x.last_name_update, x.name))
    return out
