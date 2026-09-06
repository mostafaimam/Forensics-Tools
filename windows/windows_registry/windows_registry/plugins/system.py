"""Plugins for the SYSTEM hive."""

from __future__ import annotations

import struct

from windows_registry.hive import RegistryHive, to_text
from windows_registry.plugins._base import (
    SYSTEM,
    control_sets,
    dt_to_iso,
    ft_to_iso,
    plugin,
    subkey,
    u32,
    value_text,
    values_dict,
)

_START = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
_TYPE = {1: "kernel-driver", 2: "fs-driver", 16: "own-process",
         32: "shared-process", 272: "own-interactive", 288: "shared-interactive"}


@plugin("computer-info", "Computer name, time zone, last shutdown", (SYSTEM,))
def computer_info(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        cn = hive.get(f"{cs}\\Control\\ComputerName\\ComputerName")
        tz = hive.get(f"{cs}\\Control\\TimeZoneInformation")
        wd = hive.get(f"{cs}\\Control\\Windows")
        row = {"control_set": cs,
               "computer_name": value_text(cn, "ComputerName"),
               "time_zone": value_text(tz, "TimeZoneKeyName"),
               "active_bias": value_text(tz, "ActiveTimeBias"),
               "last_shutdown_utc": ft_to_iso(_qword(wd, "ShutdownTime"))}
        rows.append(row)
    return rows


def _qword(key, name):
    d = values_dict(key)
    v = d.get(name)
    if v and isinstance(v.raw_data, (bytes, bytearray)) and len(v.raw_data) >= 8:
        return struct.unpack_from("<Q", v.raw_data, 0)[0]
    return 0


@plugin("services", "Windows services and drivers - image path, start, account",
        (SYSTEM,))
def services(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        svc = hive.get(f"{cs}\\Services")
        if not svc:
            continue
        for s in svc.subkeys():
            d = {v.name.lower(): to_text(v.data) for v in s.values()}
            iv = values_dict(s)
            rows.append({
                "control_set": cs, "service": s.name,
                "display_name": d.get("displayname", ""),
                "image_path": d.get("imagepath", ""),
                "service_dll": value_text(subkey(s, "Parameters"), "ServiceDll"),
                "start": _START.get(u32(iv["Start"].data) if "Start" in iv else -1,
                                    d.get("start", "")),
                "type": _TYPE.get(u32(iv["Type"].data) if "Type" in iv else -1,
                                  d.get("type", "")),
                "object_name": d.get("objectname", ""),
                "key_last_written": dt_to_iso(s.last_written),
            })
    return rows


@plugin("bam", "Background Activity Moderator - last execution time per binary",
        (SYSTEM,))
def bam(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        for svc in ("bam", "dam"):
            base = hive.get(f"{cs}\\Services\\{svc}\\State\\UserSettings") or \
                hive.get(f"{cs}\\Services\\{svc}\\UserSettings")
            if not base:
                continue
            for sid in base.subkeys():
                for v in sid.values():
                    if v.name in ("(default)", "Version", "SequenceNumber"):
                        continue
                    raw = v.raw_data if isinstance(v.raw_data,
                                                   (bytes, bytearray)) else b""
                    ft = struct.unpack_from("<Q", raw, 0)[0] if len(raw) >= 8 else 0
                    rows.append({"source": svc, "sid": sid.name,
                                 "path": v.name,
                                 "last_execution_utc": ft_to_iso(ft)})
    return rows


@plugin("usbstor", "USB mass-storage device history", (SYSTEM,))
def usbstor(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        k = hive.get(f"{cs}\\Enum\\USBSTOR")
        if not k:
            continue
        for dev in k.subkeys():
            for inst in dev.subkeys():
                d = {v.name.lower(): to_text(v.data) for v in inst.values()}
                props = _device_dates(inst)
                rows.append({
                    "control_set": cs, "device": dev.name,
                    "serial": inst.name,
                    "friendly_name": d.get("friendlyname", ""),
                    "first_connected_utc": props.get("0064", ""),
                    "last_connected_utc": props.get("0066", ""),
                    "last_removed_utc": props.get("0067", ""),
                    "key_last_written": dt_to_iso(inst.last_written),
                })
    return rows


def _device_dates(inst):
    """Read the {83da6326-97a6-4088-9453-a1923f573b29} device-property GUIDs."""
    out = {}
    props = subkey(inst, "Properties")
    if not props:
        return out
    guid = subkey(props, "{83da6326-97a6-4088-9453-a1923f573b29}")
    if not guid:
        return out
    for pid in guid.subkeys():
        for v in pid.values():
            if isinstance(v.raw_data, (bytes, bytearray)) and len(v.raw_data) >= 8:
                out[pid.name.lstrip("0") or "0"] = ft_to_iso(
                    struct.unpack_from("<Q", v.raw_data, 0)[0])
    return out


@plugin("usb-devices", "All USB devices (Enum\\USB) with VID/PID", (SYSTEM,))
def usb_devices(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        k = hive.get(f"{cs}\\Enum\\USB")
        if not k:
            continue
        for dev in k.subkeys():
            for inst in dev.subkeys():
                d = {v.name.lower(): to_text(v.data) for v in inst.values()}
                rows.append({"control_set": cs, "device": dev.name,
                             "instance": inst.name,
                             "friendly_name": d.get("friendlyname", ""),
                             "device_desc": d.get("devicedesc", ""),
                             "key_last_written": dt_to_iso(inst.last_written)})
    return rows


@plugin("network-interfaces", "TCP/IP interface configuration and DHCP leases",
        (SYSTEM,))
def network_interfaces(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        k = hive.get(f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces")
        if not k:
            continue
        for iface in k.subkeys():
            d = {v.name: to_text(v.data) for v in iface.values()}
            rows.append({
                "control_set": cs, "interface": iface.name,
                "dhcp_enabled": d.get("EnableDHCP", ""),
                "ip_address": d.get("IPAddress") or d.get("DhcpIPAddress", ""),
                "subnet": d.get("SubnetMask") or d.get("DhcpSubnetMask", ""),
                "gateway": d.get("DefaultGateway") or d.get("DhcpDefaultGateway",
                                                            ""),
                "dhcp_server": d.get("DhcpServer", ""),
                "name_server": d.get("NameServer") or d.get("DhcpNameServer", ""),
                "domain": d.get("Domain") or d.get("DhcpDomain", ""),
                "lease_obtained_utc": ft_to_iso(u32(
                    _raw(iface, "LeaseObtainedTime")) * 10_000_000
                    + 116444736000000000 if _raw(iface, "LeaseObtainedTime")
                    else 0),
            })
    return rows


def _raw(key, name):
    v = values_dict(key).get(name)
    return v.data if v else 0


@plugin("session-manager", "Session Manager - BootExecute, pending renames, env",
        (SYSTEM,))
def session_manager(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        sm = hive.get(f"{cs}\\Control\\Session Manager")
        if not sm:
            continue
        for name in ("BootExecute", "SetupExecute", "Execute", "S0InitialCommand"):
            v = value_text(sm, name)
            if v and v not in ("autocheck autochk *",):
                rows.append({"control_set": cs, "setting": name, "value": v})
        pfr = values_dict(sm).get("PendingFileRenameOperations")
        if pfr and isinstance(pfr.raw_data, (bytes, bytearray)):
            parts = [p for p in pfr.raw_data.decode("utf-16-le", "ignore")
                     .split("\x00") if p]
            for i in range(0, len(parts) - 1, 2):
                rows.append({"control_set": cs,
                             "setting": "PendingFileRename",
                             "value": f"{parts[i]}  ->  {parts[i+1] or '(delete)'}"})
        kmm = subkey(sm, "Memory Management")
        cd = value_text(kmm, "PagingFiles") if kmm else ""
        if cd:
            rows.append({"control_set": cs, "setting": "PagingFiles", "value": cd})
    return rows


@plugin("lsa", "LSA security / authentication / notification packages", (SYSTEM,))
def lsa(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        lsak = hive.get(f"{cs}\\Control\\Lsa")
        if not lsak:
            continue
        for name in ("Security Packages", "Authentication Packages",
                     "Notification Packages"):
            v = value_text(lsak, name)
            if v:
                rows.append({"control_set": cs, "setting": name,
                             "value": v.replace("\n", " | ")})
        wd = subkey(lsak, "SecurityProviders")
        wdig = subkey(wd, "WDigest") if wd else subkey(lsak, "WDigest")
        if wdig:
            rows.append({"control_set": cs, "setting": "WDigest UseLogonCredential",
                         "value": value_text(wdig, "UseLogonCredential")})
    return rows


@plugin("run-on-boot", "BootExecute / knowndlls / safeboot alternate shells",
        (SYSTEM,))
def run_on_boot(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        kd = hive.get(f"{cs}\\Control\\Session Manager\\KnownDLLs")
        if kd:
            for v in kd.values():
                if v.name not in ("(default)", "DllDirectory",
                                  "DllDirect32"):
                    rows.append({"control_set": cs, "type": "KnownDLL",
                                 "name": v.name, "value": to_text(v.data)})
    return rows


@plugin("terminal-server", "Remote Desktop configuration", (SYSTEM,))
def terminal_server(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        ts = hive.get(f"{cs}\\Control\\Terminal Server")
        if not ts:
            continue
        rows.append({
            "control_set": cs,
            "rdp_disabled": value_text(ts, "fDenyTSConnections"),
            "port": value_text(subkey(subkey(ts, "WinStations"), "RDP-Tcp")
                               if subkey(ts, "WinStations") else None,
                               "PortNumber"),
            "user_auth_required": value_text(
                subkey(subkey(ts, "WinStations"), "RDP-Tcp")
                if subkey(ts, "WinStations") else None, "UserAuthentication"),
        })
    return rows


@plugin("portproxy", "netsh portproxy port-forwarding rules", (SYSTEM,))
def portproxy(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        for proto in ("v4tov4", "v6tov4", "v4tov6", "v6tov6"):
            for tp in ("tcp", "udp"):
                k = hive.get(f"{cs}\\Services\\PortProxy\\{proto}\\{tp}")
                if not k:
                    continue
                for v in k.values():
                    if v.name != "(default)":
                        rows.append({"control_set": cs, "protocol": f"{proto}/{tp}",
                                     "listen": v.name, "forward_to": to_text(v.data)})
    return rows


@plugin("firewall-rules", "Windows Firewall rules (allow/block, program, port)",
        (SYSTEM,))
def firewall_rules(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        for scope in ("FirewallRules", "RestrictedServices\\Static\\System"):
            k = hive.get(f"{cs}\\Services\\SharedAccess\\Parameters\\"
                         f"FirewallPolicy\\{scope}")
            if not k:
                continue
            for v in k.values():
                if v.name == "(default)":
                    continue
                parts = dict(p.split("=", 1) for p in to_text(v.data).split("|")
                             if "=" in p)
                rows.append({
                    "control_set": cs, "rule": v.name,
                    "action": parts.get("Action", ""),
                    "direction": parts.get("Dir", ""),
                    "name": parts.get("Name", ""),
                    "app": parts.get("App", ""),
                    "port": parts.get("LPort", parts.get("RPort", "")),
                    "enabled": parts.get("Active", ""),
                })
    return rows


@plugin("print-monitors", "Print monitors and processors (persistence surface)",
        (SYSTEM,))
def print_monitors(hive: RegistryHive):
    rows = []
    for cs in control_sets(hive):
        for kind in ("Monitors", "Print Processors"):
            k = hive.get(f"{cs}\\Control\\Print\\{kind}")
            if not k:
                continue
            for m in k.subkeys():
                rows.append({"control_set": cs, "kind": kind, "name": m.name,
                             "driver": value_text(m, "Driver"),
                             "key_last_written": dt_to_iso(m.last_written)})
    return rows


@plugin("mounted-devices", "MountedDevices - volume to drive-letter / device map",
        (SYSTEM,))
def mounted_devices(hive: RegistryHive):
    k = hive.get("MountedDevices")
    if not k:
        return []
    rows = []
    for v in k.values():
        raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) else b""
        if len(raw) == 12:                        # MBR disk signature + offset
            sig = raw[:4].hex().upper()
            off = struct.unpack_from("<Q", raw, 4)[0]
            pretty = f"MBR sig {sig}, offset {off}"
        elif b"\x00" in raw:
            pretty = raw.decode("utf-16-le", "ignore")
        else:
            pretty = raw.hex().upper()
        rows.append({"name": v.name, "value": pretty})
    return rows
