"""Pull USB / USBSTOR / MountedDevices data out of the hives."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from windows_usbdevices.hive import RegistryHive

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# device-property GUIDs / PIDs holding the timestamps
_PROP_INSTALL = ("{83da6326-97a6-4088-9453-a1923f573b29}", "0064")   # InstallDate
_PROP_FIRSTINSTALL = ("{83da6326-97a6-4088-9453-a1923f573b29}", "0065")
_PROP_LASTARRIVAL = ("{83da6326-97a6-4088-9453-a1923f573b29}", "0066")
_PROP_LASTREMOVAL = ("{83da6326-97a6-4088-9453-a1923f573b29}", "0067")


def _ft(raw) -> str:
    if isinstance(raw, str):
        return raw
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        return ""
    t = struct.unpack_from("<Q", raw, 0)[0]
    if t <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=t / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class Device:
    kind: str = "usbstor"
    vendor: str = ""
    product: str = ""
    revision: str = ""
    serial: str = ""
    serial_synthetic: bool = False       # trailing '&0' => no real serial
    friendly_name: str = ""
    vid: str = ""
    pid: str = ""
    container_id: str = ""
    parent_prefix_id: str = ""
    drive_letters: list = field(default_factory=list)
    volume_guids: list = field(default_factory=list)
    volume_name: str = ""
    install: str = ""
    first_install: str = ""
    last_arrival: str = ""
    last_removal: str = ""
    setupapi_first_seen: str = ""
    diskid: str = ""
    notable: list = field(default_factory=list)

    def key(self) -> str:
        return self.serial or f"{self.vendor}_{self.product}"

    def row(self) -> dict:
        return {
            "vendor": self.vendor, "product": self.product,
            "revision": self.revision, "serial": self.serial,
            "serial_synthetic": "yes" if self.serial_synthetic else "",
            "friendly_name": self.friendly_name,
            "vid": self.vid, "pid": self.pid,
            "container_id": self.container_id,
            "drive_letters": ",".join(self.drive_letters),
            "volume_guids": ",".join(self.volume_guids),
            "volume_name": self.volume_name,
            "first_connected": self.first_install or self.install
            or self.setupapi_first_seen,
            "install": self.install, "last_arrival": self.last_arrival,
            "last_removal": self.last_removal,
            "setupapi_first_seen": self.setupapi_first_seen,
            "notable": ";".join(self.notable),
        }


def _val(key, name):
    for v in key.values():
        if v.name.lower() == name.lower():
            return v.data if not isinstance(v.data, (bytes, bytearray)) \
                else v.raw_data
    return None


def _prop_ts(dev_key, guid, pid) -> str:
    try:
        pk = None
        for sub in dev_key.subkeys():
            if sub.name.lower() == "properties":
                pk = sub
                break
        if pk is None:
            return ""
        for g in pk.subkeys():
            if g.name.lower() != guid.lower():
                continue
            for p in g.subkeys():
                if p.name.lower().lstrip("0") == pid.lstrip("0") or \
                        p.name.lower() == pid.lower():
                    for v in p.values():
                        return _ft(v.raw_data if isinstance(
                            v.raw_data, (bytes, bytearray)) else v.data)
    except Exception:                            # noqa: BLE001 vendored
        return ""
    return ""


_USBSTOR_NAME = re.compile(
    r"^(Disk|CdRom|Other|Floppy)?&?Ven_([^&]*)&Prod_([^&]*)(?:&Rev_([^&]*))?$",
    re.I)


def _control_sets(hive):
    for sub in hive.root().subkeys():
        n = sub.name.lower()
        if n in ("currentcontrolset", "controlset001", "controlset002"):
            yield sub.name


def from_system_hive(data: bytes):
    devices: dict[str, Device] = {}
    try:
        hive = RegistryHive(data)
    except Exception:                            # noqa: BLE001
        return devices, {}

    cs = next(iter(_control_sets(hive)), "ControlSet001")

    usbstor = hive.get(f"{cs}\\Enum\\USBSTOR")
    if usbstor is not None:
        for prod_key in usbstor.subkeys():
            m = _USBSTOR_NAME.match(prod_key.name)
            vendor = product = revision = ""
            if m:
                vendor, product, revision = (m.group(2) or "",
                                             m.group(3) or "",
                                             m.group(4) or "")
            for inst in prod_key.subkeys():
                serial = inst.name
                synthetic = serial.endswith("&0") or serial.endswith("&1")
                d = Device(kind="usbstor", vendor=vendor.replace("_", " "),
                           product=product.replace("_", " "),
                           revision=revision, serial=serial,
                           serial_synthetic=synthetic)
                fn = _val(inst, "FriendlyName")
                if isinstance(fn, str):
                    d.friendly_name = fn
                pp = _val(inst, "ParentIdPrefix")
                if isinstance(pp, str):
                    d.parent_prefix_id = pp
                cid = _val(inst, "ContainerID")
                if isinstance(cid, str):
                    d.container_id = cid
                d.install = _prop_ts(inst, *_PROP_INSTALL)
                d.first_install = _prop_ts(inst, *_PROP_FIRSTINSTALL)
                d.last_arrival = _prop_ts(inst, *_PROP_LASTARRIVAL)
                d.last_removal = _prop_ts(inst, *_PROP_LASTREMOVAL)
                devices[serial] = d

    usb = hive.get(f"{cs}\\Enum\\USB")
    if usb is not None:
        for vp_key in usb.subkeys():
            vp = re.match(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})",
                          vp_key.name)
            if not vp:
                continue
            for inst in vp_key.subkeys():
                d = devices.get(inst.name)
                if d is None:
                    continue
                d.vid, d.pid = vp.group(1).upper(), vp.group(2).upper()
                cid = _val(inst, "ContainerID")
                if isinstance(cid, str):
                    d.container_id = d.container_id or cid

    # MountedDevices: drive letter / volume -> value bytes containing the
    # \??\USBSTOR#... string (or the ParentIdPrefix)
    mounted = hive.get("MountedDevices")
    mount_map: dict[str, list[str]] = {}
    if mounted is not None:
        for v in mounted.values():
            raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) \
                else b""
            try:
                txt = bytes(raw).decode("utf-16-le", "replace")
            except Exception:                    # noqa: BLE001
                txt = ""
            name = v.name
            label = ""
            if name.startswith("\\DosDevices\\"):
                label = name[len("\\DosDevices\\"):]
            elif name.startswith("\\??\\Volume"):
                label = name[4:]
            if not label:
                continue
            for d in devices.values():
                token = (d.serial.split("&")[0] if d.serial else "")
                if (d.serial and d.serial in txt) or \
                        (d.parent_prefix_id and d.parent_prefix_id in txt) or \
                        (token and token in txt):
                    if len(label) <= 3 and label.endswith(":"):
                        d.drive_letters.append(label)
                    else:
                        d.volume_guids.append(label)
                    mount_map.setdefault(d.serial, []).append(label)
    return devices, mount_map


def from_software_hive(data: bytes, devices: dict):
    try:
        hive = RegistryHive(data)
    except Exception:                            # noqa: BLE001
        return
    wpd = hive.get(r"Microsoft\Windows Portable Devices\Devices")
    if wpd is None:
        return
    for dev in wpd.subkeys():
        fn = _val(dev, "FriendlyName")
        if not isinstance(fn, str):
            continue
        low = dev.name.lower()
        for d in devices.values():
            if (d.serial and d.serial.lower() in low) or \
                    (d.parent_prefix_id and d.parent_prefix_id.lower() in low):
                d.volume_name = fn
