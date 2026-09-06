"""Built-in extraction recipes (plugins).

Each plugin is a function ``run(hive) -> list[dict]``.  They probe several
candidate paths so the same plugin works whether it is handed an `NTUSER.DAT`,
a `SOFTWARE` or a `SYSTEM` hive.
"""

from __future__ import annotations

import codecs
import struct
from datetime import datetime, timedelta, timezone

from windows_registry.hive import Key, RegistryHive, to_text

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(ticks: int):
    if ticks <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _first(hive: RegistryHive, *paths) -> Key | None:
    for p in paths:
        k = hive.get(p)
        if k is not None:
            return k
    return None


def _control_sets(hive: RegistryHive):
    for name in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        k = hive.get(name)
        if k:
            yield name, k


# --------------------------------------------------------------------------
def run_keys(hive: RegistryHive) -> list[dict]:
    rows = []
    bases = [
        "Software\\Microsoft\\Windows\\CurrentVersion",
        "Microsoft\\Windows\\CurrentVersion",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
    ]
    subs = ["Run", "RunOnce", "RunServices", "RunServicesOnce",
            "RunOnceEx", "Policies\\Explorer\\Run"]
    for b in bases:
        for s in subs:
            k = hive.get(f"{b}\\{s}")
            if not k:
                continue
            for v in k.values():
                if v.name == "(default)":
                    continue
                rows.append({
                    "location": f"{b}\\{s}", "name": v.name,
                    "command": to_text(v.data),
                    "key_last_written": _fmt(k.last_written),
                })
    return rows


def services(hive: RegistryHive) -> list[dict]:
    rows = []
    start_names = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual",
                   4: "Disabled"}
    for cs_name, cs in _control_sets(hive):
        svc = None
        for sub in cs.subkeys():
            if sub.name.lower() == "services":
                svc = sub
                break
        if not svc:
            continue
        for s in svc.subkeys():
            vals = {v.name.lower(): v for v in s.values()}
            def g(n):
                v = vals.get(n)
                return to_text(v.data) if v else ""
            rows.append({
                "control_set": cs_name, "service": s.name,
                "display_name": g("displayname"),
                "image_path": g("imagepath"),
                "start": start_names.get(_int(vals.get("start")), g("start")),
                "type": _int(vals.get("type")),
                "object_name": g("objectname"),
                "last_written": _fmt(s.last_written),
            })
    return rows


def uninstall(hive: RegistryHive) -> list[dict]:
    rows = []
    for p in ("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
              "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
              "Microsoft\\Windows\\CurrentVersion\\Uninstall"):
        k = hive.get(p)
        if not k:
            continue
        for app in k.subkeys():
            vals = {v.name.lower(): to_text(v.data) for v in app.values()}
            rows.append({
                "key": app.name,
                "display_name": vals.get("displayname", ""),
                "version": vals.get("displayversion", ""),
                "publisher": vals.get("publisher", ""),
                "install_date": vals.get("installdate", ""),
                "install_location": vals.get("installlocation", ""),
                "last_written": _fmt(app.last_written),
            })
    return rows


def userassist(hive: RegistryHive) -> list[dict]:
    rows = []
    ua = _first(hive,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    if not ua:
        return rows
    for guid in ua.subkeys():
        count = None
        for c in guid.subkeys():
            if c.name.lower() == "count":
                count = c
                break
        if not count:
            continue
        for v in count.values():
            if v.name == "(default)":
                continue
            name = codecs.decode(v.name, "rot_13")
            raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) else b""
            runs = focus = last = None
            if len(raw) >= 16:
                runs = struct.unpack_from("<I", raw, 4)[0]
            if len(raw) >= 68:
                last = struct.unpack_from("<Q", raw, 60)[0]
            rows.append({
                "guid": guid.name, "name": name,
                "run_count": runs if runs is not None else "",
                "last_executed_utc": _ft(last) if last else "",
            })
    return rows


def typed_urls(hive: RegistryHive) -> list[dict]:
    k = _first(hive,
               "Software\\Microsoft\\Internet Explorer\\TypedURLs",
               "Microsoft\\Internet Explorer\\TypedURLs")
    if not k:
        return []
    return [{"name": v.name, "url": to_text(v.data),
             "key_last_written": _fmt(k.last_written)}
            for v in k.values() if v.name != "(default)"]


def computer_info(hive: RegistryHive) -> list[dict]:
    rows = []
    for cs_name, cs in _control_sets(hive):
        cn = hive.get(f"{cs_name}\\Control\\ComputerName\\ComputerName")
        tz = hive.get(f"{cs_name}\\Control\\TimeZoneInformation")
        row = {"control_set": cs_name}
        if cn:
            for v in cn.values():
                if v.name.lower() == "computername":
                    row["computer_name"] = to_text(v.data)
        if tz:
            for v in tz.values():
                if v.name.lower() in ("timezonekeyname", "standardname",
                                      "daylightname", "activetimebias", "bias"):
                    row[v.name.lower()] = to_text(v.data)
        if len(row) > 1:
            rows.append(row)
    return rows


def mounted_devices(hive: RegistryHive) -> list[dict]:
    k = hive.get("MountedDevices")
    if not k:
        return []
    rows = []
    for v in k.values():
        raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) else b""
        pretty = raw.decode("utf-16-le", "replace") if len(raw) < 64 and \
            b"\x00" in raw else raw.hex().upper()
        rows.append({"name": v.name, "value": pretty})
    return rows


def usbstor(hive: RegistryHive) -> list[dict]:
    rows = []
    for cs_name, _cs in _control_sets(hive):
        k = hive.get(f"{cs_name}\\Enum\\USBSTOR")
        if not k:
            continue
        for dev in k.subkeys():
            for inst in dev.subkeys():
                vals = {v.name.lower(): to_text(v.data) for v in inst.values()}
                rows.append({
                    "control_set": cs_name,
                    "device": dev.name,
                    "serial": inst.name,
                    "friendly_name": vals.get("friendlyname", ""),
                    "first_seen_key_written": _fmt(inst.last_written),
                })
    return rows


def _int(v) -> int:
    if v is None:
        return -1
    d = v.data
    return d if isinstance(d, int) else -1


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else ""


PLUGINS = {
    "run-keys": (run_keys, "Autostart entries (Run / RunOnce / ...)"),
    "services": (services, "Windows services (SYSTEM hive)"),
    "uninstall": (uninstall, "Installed programs (Uninstall keys)"),
    "userassist": (userassist, "UserAssist GUI program execution (NTUSER)"),
    "typed-urls": (typed_urls, "Internet Explorer typed URLs (NTUSER)"),
    "computer-info": (computer_info, "Computer name and time zone (SYSTEM)"),
    "mounted-devices": (mounted_devices, "MountedDevices (SYSTEM)"),
    "usbstor": (usbstor, "USB mass-storage device history (SYSTEM)"),
}
