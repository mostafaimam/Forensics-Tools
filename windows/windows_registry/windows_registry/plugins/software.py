"""Plugins for the SOFTWARE hive."""

from __future__ import annotations

from windows_registry.hive import RegistryHive, to_text
from windows_registry.plugins._base import (
    SOFTWARE,
    dt_to_iso,
    first_key,
    ft_to_iso,
    plugin,
    subkey,
    systemtime_to_iso,
    u32,
    value_text,
    values_dict,
)

_MSW = "Microsoft\\Windows\\CurrentVersion"
_MSWNT = "Microsoft\\Windows NT\\CurrentVersion"
_W64 = "Wow6432Node\\"


@plugin("os-info", "Operating-system version, build and install date", (SOFTWARE,))
def os_info(hive: RegistryHive):
    k = hive.get(_MSWNT)
    if not k:
        return []
    d = {v.name: v for v in k.values()}

    def g(n):
        return to_text(d[n].data) if n in d else ""
    install = d.get("InstallDate")
    installed = ft_to_iso(u32(install.data) * 10_000_000 + 116444736000000000) \
        if install else ""
    return [{
        "product_name": g("ProductName"),
        "edition": g("EditionID"),
        "release_id": g("ReleaseId") or g("DisplayVersion"),
        "build": f"{g('CurrentBuild')}.{g('UBR')}" if "UBR" in d else g("CurrentBuild"),
        "build_lab": g("BuildLabEx") or g("BuildLab"),
        "registered_owner": g("RegisteredOwner"),
        "registered_org": g("RegisteredOrganization"),
        "install_date_utc": installed,
        "install_time_utc": ft_to_iso(
            int.from_bytes(d["InstallTime"].raw_data, "little")
            if "InstallTime" in d and isinstance(d["InstallTime"].raw_data,
                                                 (bytes, bytearray)) else 0),
        "system_root": g("SystemRoot"),
    }]


@plugin("winlogon", "Winlogon configuration (shell, userinit, autologon, notify)",
        (SOFTWARE,))
def winlogon(hive: RegistryHive):
    k = hive.get(f"{_MSWNT}\\Winlogon")
    if not k:
        return []
    d = {v.name: to_text(v.data) for v in k.values()}
    rows = [{
        "setting": name, "value": d.get(name, "")
    } for name in ("Shell", "Userinit", "System", "VmApplet", "GinaDLL",
                   "AppSetup", "Taskman", "AutoAdminLogon", "DefaultUserName",
                   "DefaultDomainName", "DefaultPassword", "ForceAutoLogon")
        if name in d]
    for sub_name in ("Notify",):
        s = subkey(k, sub_name)
        if s:
            for n in s.subkeys():
                rows.append({"setting": f"Notify\\{n.name}",
                             "value": value_text(n, "DLLName")})
    return rows


@plugin("appinit-dlls", "AppInit_DLLs and other NT-Windows load points", (SOFTWARE,))
def appinit_dlls(hive: RegistryHive):
    rows = []
    for path in (f"{_MSWNT}\\Windows", f"{_W64}{_MSWNT}\\Windows"):
        k = hive.get(path)
        if not k:
            continue
        for name in ("AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs"):
            val = value_text(k, name)
            if val not in ("", "0"):
                rows.append({"key": path, "name": name, "value": val})
    for name in ("Load", "Run"):
        v = value_text(hive.get(f"{_MSWNT}\\Windows"), name)
        if v:
            rows.append({"key": f"{_MSWNT}\\Windows", "name": name, "value": v})
    return rows


@plugin("ifeo", "Image File Execution Options - debugger / GlobalFlag hijacks",
        (SOFTWARE,))
def ifeo(hive: RegistryHive):
    k = hive.get(f"{_MSWNT}\\Image File Execution Options")
    if not k:
        return []
    rows = []
    for exe in k.subkeys():
        d = {v.name.lower(): to_text(v.data) for v in exe.values()}
        if "debugger" in d or "globalflag" in d or exe.subkeys():
            row = {"image": exe.name}
            if "debugger" in d:
                row["debugger"] = d["debugger"]
            if "globalflag" in d:
                row["global_flag"] = d["globalflag"]
            se = subkey(exe, "SilentProcessExit")
            if se:
                row["silent_process_exit"] = value_text(se, "MonitorProcess")
            if len(row) > 1:
                rows.append(row)
    return rows


@plugin("app-paths", "App Paths - registered application executables", (SOFTWARE,))
def app_paths(hive: RegistryHive):
    rows = []
    for base in (f"{_MSW}\\App Paths", f"{_W64}{_MSW}\\App Paths"):
        k = hive.get(base)
        if not k:
            continue
        for app in k.subkeys():
            rows.append({"name": app.name,
                         "path": value_text(app, "(default)")
                         or value_text(app, ""),
                         "key_last_written": dt_to_iso(app.last_written)})
    return rows


@plugin("profilelist", "ProfileList - SID to user-profile mapping", (SOFTWARE,))
def profilelist(hive: RegistryHive):
    k = hive.get(f"{_MSWNT}\\ProfileList")
    if not k:
        return []
    rows = []
    for sid in k.subkeys():
        if not sid.name.startswith("S-1-"):
            continue
        rows.append({
            "sid": sid.name,
            "profile_path": value_text(sid, "ProfileImagePath"),
            "flags": u32(values_dict(sid).get("Flags").data
                         if "Flags" in values_dict(sid) else 0),
            "load_time_utc": _profile_time(sid, "ProfileLoadTimeHigh",
                                           "ProfileLoadTimeLow"),
        })
    return rows


def _profile_time(key, hi_name, lo_name):
    d = values_dict(key)
    if hi_name in d and lo_name in d:
        ticks = (u32(d[hi_name].data) << 32) | u32(d[lo_name].data)
        return ft_to_iso(ticks)
    return ""


@plugin("networklist", "Wi-Fi / wired networks: name, first & last connected",
        (SOFTWARE,))
def networklist(hive: RegistryHive):
    profiles = hive.get(f"{_MSWNT}\\NetworkList\\Profiles")
    if not profiles:
        return []
    sigs = {}
    for kind in ("Managed", "Unmanaged"):
        sk = hive.get(f"{_MSWNT}\\NetworkList\\Signatures\\{kind}")
        if sk:
            for s in sk.subkeys():
                guid = value_text(s, "ProfileGuid")
                if guid:
                    sigs[guid] = {
                        "gateway_mac": _mac(values_dict(s).get(
                            "DefaultGatewayMac")),
                        "dns_suffix": value_text(s, "DnsSuffix"),
                        "first_network": value_text(s, "FirstNetwork"),
                    }
    rows = []
    _cat = {0: "Public", 1: "Private", 2: "Domain"}
    for p in profiles.subkeys():
        d = values_dict(p)
        rows.append({
            "profile_name": value_text(p, "ProfileName"),
            "description": value_text(p, "Description"),
            "category": _cat.get(u32(d["Category"].data)
                                 if "Category" in d else -1, ""),
            "date_created_utc": systemtime_to_iso(
                d["DateCreated"].raw_data if "DateCreated" in d
                and isinstance(d["DateCreated"].raw_data, (bytes, bytearray))
                else b""),
            "date_last_connected_utc": systemtime_to_iso(
                d["DateLastConnected"].raw_data if "DateLastConnected" in d
                and isinstance(d["DateLastConnected"].raw_data, (bytes, bytearray))
                else b""),
            **sigs.get(p.name, {}),
        })
    return rows


def _mac(v):
    if v is None or not isinstance(v.raw_data, (bytes, bytearray)):
        return ""
    b = v.raw_data[:6]
    return ":".join(f"{x:02x}" for x in b) if any(b) else ""


@plugin("defender-exclusions", "Windows Defender exclusions (paths / ext / procs)",
        (SOFTWARE,))
def defender_exclusions(hive: RegistryHive):
    base = first_key(hive, "Microsoft\\Windows Defender\\Exclusions",
                     "Policies\\Microsoft\\Windows Defender\\Exclusions")
    if not base:
        return []
    rows = []
    for kind in base.subkeys():
        for v in kind.values():
            if v.name != "(default)":
                rows.append({"type": kind.name, "value": v.name})
    return rows


@plugin("powershell-logging", "PowerShell script-block / module / transcript logging",
        (SOFTWARE,))
def powershell_logging(hive: RegistryHive):
    rows = []
    for base in ("Policies\\Microsoft\\Windows\\PowerShell",
                 "Microsoft\\PowerShell"):
        for feat in ("ScriptBlockLogging", "ModuleLogging", "Transcription"):
            k = hive.get(f"{base}\\{feat}")
            if not k:
                continue
            for v in k.values():
                if v.name != "(default)":
                    rows.append({"feature": feat, "setting": v.name,
                                 "value": to_text(v.data)})
    return rows


@plugin("taskcache", "Scheduled tasks registered on the system (TaskCache)",
        (SOFTWARE,))
def taskcache(hive: RegistryHive):
    tasks = hive.get(f"{_MSWNT}\\Schedule\\TaskCache\\Tasks")
    tree = hive.get(f"{_MSWNT}\\Schedule\\TaskCache\\Tree")
    if not tasks:
        return []
    name_by_guid = {}
    if tree:
        for t in hive.walk(tree):
            g = value_text(t, "Id")
            if g:
                name_by_guid[g] = t.path.split("Tree\\", 1)[-1]
    rows = []
    for g in tasks.subkeys():
        d = values_dict(g)
        rows.append({
            "guid": g.name,
            "task_name": name_by_guid.get(g.name, ""),
            "action_path": _task_action(d.get("Actions")),
            "created_utc": value_text(g, "Date"),
            "author": value_text(g, "Author"),
        })
    return rows


def _task_action(v):
    if v is None or not isinstance(v.raw_data, (bytes, bytearray)):
        return ""
    txt = v.raw_data.decode("utf-16-le", "ignore")
    return "".join(c for c in txt if c.isprintable())[:200]


@plugin("shell-folders", "User Shell Folders - redirected profile locations",
        (SOFTWARE,))
def shell_folders(hive: RegistryHive):
    rows = []
    for base in (f"{_MSW}\\Explorer\\User Shell Folders",
                 f"{_MSW}\\Explorer\\Shell Folders"):
        k = hive.get(base)
        if not k:
            continue
        for v in k.values():
            if v.name != "(default)":
                rows.append({"key": base.split("\\")[-1],
                             "folder": v.name, "path": to_text(v.data)})
    return rows
