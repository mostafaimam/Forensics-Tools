"""Plugins for NTUSER.DAT (and, where noted, UsrClass.dat)."""

from __future__ import annotations

import struct

from windows_registry.hive import RegistryHive, to_text
from windows_registry.plugins._base import (
    NTUSER,
    USRCLASS,
    dt_to_iso,
    first_key,
    ft_to_iso,
    mrulistex_order,
    plugin,
    rot13,
    subkey,
    u32,
    value_text,
    values_dict,
)

_CV = [
    "Software\\Microsoft\\Windows\\CurrentVersion",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
]


def _cv(hive, tail):
    return first_key(hive, *(f"{b}\\{tail}" for b in _CV))


@plugin("run-keys", "Autostart entries (Run / RunOnce / policy Run)", (NTUSER,))
def run_keys(hive: RegistryHive):
    rows = []
    for sub in ("Run", "RunOnce", "RunServices", "RunServicesOnce", "RunOnceEx",
                "Policies\\Explorer\\Run"):
        k = _cv(hive, sub) or hive.get(
            f"Software\\Microsoft\\Windows\\CurrentVersion\\{sub}")
        if not k:
            continue
        for v in k.values():
            if v.name != "(default)":
                rows.append({"location": sub, "name": v.name,
                             "command": to_text(v.data),
                             "key_last_written": dt_to_iso(k.last_written)})
    return rows


@plugin("userassist", "UserAssist - GUI program execution (name, count, last run)",
        (NTUSER,))
def userassist(hive: RegistryHive):
    ua = _cv(hive, "Explorer\\UserAssist")
    if not ua:
        return []
    rows = []
    for guid in ua.subkeys():
        count = subkey(guid, "Count")
        if not count:
            continue
        for v in count.values():
            if v.name == "(default)":
                continue
            name = rot13(v.name)
            raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) else b""
            runs = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else None
            last = struct.unpack_from("<Q", raw, 60)[0] if len(raw) >= 68 else 0
            rows.append({"guid": guid.name, "name": name,
                         "run_count": runs if runs is not None else "",
                         "last_run_utc": ft_to_iso(last),
                         "focus_seconds": (struct.unpack_from("<I", raw, 12)[0]
                                           / 1000 if len(raw) >= 16 else "")})
    return rows


@plugin("recentdocs", "RecentDocs - files opened via the shell, per extension",
        (NTUSER,))
def recentdocs(hive: RegistryHive):
    rd = _cv(hive, "Explorer\\RecentDocs")
    if not rd:
        return []
    rows = []

    def _emit(key, ext):
        vals = {v.name: v for v in key.values()}
        order = mrulistex_order(vals.get("MRUListEx").data
                                if "MRUListEx" in vals else b"")
        pos = {n: i for i, n in enumerate(order)}
        for v in key.values():
            if v.name in ("MRUListEx", "(default)"):
                continue
            raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) else b""
            name = raw.split(b"\x00\x00")[0].decode("utf-16-le", "replace")
            try:
                idx = int(v.name)
            except ValueError:
                idx = -1
            rows.append({"extension": ext or "(all)",
                         "mru_position": pos.get(idx, ""),
                         "name": name,
                         "key_last_written": dt_to_iso(key.last_written)})

    _emit(rd, "")
    for sub in rd.subkeys():
        _emit(sub, sub.name)
    return rows


@plugin("runmru", "Start > Run history (RunMRU)", (NTUSER,))
def runmru(hive: RegistryHive):
    k = _cv(hive, "Explorer\\RunMRU")
    if not k:
        return []
    order = value_text(k, "MRUList")
    rows = []
    for v in k.values():
        if v.name in ("MRUList", "(default)"):
            continue
        rows.append({"slot": v.name, "command": to_text(v.data).rstrip("\\1"),
                     "mru_position": order.find(v.name) if order else ""})
    return rows


@plugin("typed-paths", "Explorer address-bar typed paths", (NTUSER,))
def typed_paths(hive: RegistryHive):
    k = _cv(hive, "Explorer\\TypedPaths")
    if not k:
        return []
    return [{"name": v.name, "path": to_text(v.data),
             "key_last_written": dt_to_iso(k.last_written)}
            for v in k.values() if v.name != "(default)"]


@plugin("typed-urls", "Internet Explorer typed URLs", (NTUSER,))
def typed_urls(hive: RegistryHive):
    k = first_key(hive, "Software\\Microsoft\\Internet Explorer\\TypedURLs",
                  "Software\\Wow6432Node\\Microsoft\\Internet Explorer\\TypedURLs")
    if not k:
        return []
    times = subkey(hive.get("Software\\Microsoft\\Internet Explorer"),
                   "TypedURLsTime")
    tvals = values_dict(times)
    rows = []
    for v in k.values():
        if v.name == "(default)":
            continue
        tv = tvals.get(v.name)
        rows.append({"name": v.name, "url": to_text(v.data),
                     "typed_utc": ft_to_iso(
                         struct.unpack_from("<Q", tv.raw_data, 0)[0]
                         if tv and isinstance(tv.raw_data, (bytes, bytearray))
                         and len(tv.raw_data) >= 8 else 0)})
    return rows


@plugin("wordwheelquery", "Explorer search-bar query history", (NTUSER,))
def wordwheelquery(hive: RegistryHive):
    k = _cv(hive, "Explorer\\WordWheelQuery")
    if not k:
        return []
    vals = {v.name: v for v in k.values()}
    order = mrulistex_order(vals["MRUListEx"].data
                            if "MRUListEx" in vals else b"")
    rows = []
    for i, idx in enumerate(order):
        v = vals.get(str(idx))
        if not v:
            continue
        raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) else b""
        rows.append({"mru_position": i,
                     "query": raw.split(b"\x00\x00")[0].decode(
                         "utf-16-le", "replace"),
                     "key_last_written": dt_to_iso(k.last_written)})
    return rows


@plugin("comdlg32", "Open/Save common-dialog MRU (files and folders)", (NTUSER,))
def comdlg32(hive: RegistryHive):
    base = _cv(hive, "Explorer\\ComDlg32")
    if not base:
        return []
    rows = []
    for name in ("OpenSavePidlMRU", "LastVisitedPidlMRU", "CIDSizeMRU",
                 "OpenSaveMRU", "LastVisitedMRU"):
        k = subkey(base, name)
        if not k:
            continue
        targets = [k] + list(k.subkeys())
        for kk in targets:
            for v in kk.values():
                if v.name in ("MRUListEx", "MRUList", "(default)", "version"):
                    continue
                raw = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) \
                    else b""
                text = "".join(c for c in raw.decode("latin-1", "ignore")
                               if c.isprintable())
                rows.append({"dialog": f"{name}\\{kk.name}"
                             if kk is not k else name,
                             "slot": v.name, "hint": text[:160],
                             "key_last_written": dt_to_iso(kk.last_written)})
    return rows


@plugin("muicache", "MuiCache - applications the user has run", (NTUSER, USRCLASS))
def muicache(hive: RegistryHive):
    k = first_key(
        hive,
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        "Software\\Classes\\Local Settings\\MuiCache",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        "Local Settings\\MuiCache")
    if not k:
        return []
    rows = []
    for sub in [k] + list(k.subkeys()):
        for v in sub.values():
            if v.name in ("(default)", "LangID"):
                continue
            rows.append({"path": v.name.rsplit(".", 1)[0]
                         if v.name.lower().endswith((".friendlyappname",
                                                     ".applicationcompany"))
                         else v.name,
                         "value": to_text(v.data)})
    return rows


@plugin("mountpoints2", "MountPoints2 - volumes / shares this user mounted",
        (NTUSER,))
def mountpoints2(hive: RegistryHive):
    k = _cv(hive, "Explorer\\MountPoints2")
    if not k:
        return []
    rows = []
    for sub in k.subkeys():
        rows.append({"identifier": sub.name,
                     "label": value_text(sub, "_LabelFromReg"),
                     "kind": ("network-share" if sub.name.startswith("##")
                              else "volume-guid" if sub.name.startswith("{")
                              else "drive-letter"),
                     "key_last_written": dt_to_iso(sub.last_written)})
    return rows


@plugin("rdp-connections", "Terminal Server Client - RDP connection history",
        (NTUSER,))
def rdp_connections(hive: RegistryHive):
    base = hive.get("Software\\Microsoft\\Terminal Server Client")
    if not base:
        return []
    rows = []
    default = subkey(base, "Default")
    if default:
        for v in default.values():
            if v.name != "(default)":
                rows.append({"source": "Default", "entry": v.name,
                             "server": to_text(v.data)})
    servers = subkey(base, "Servers")
    if servers:
        for s in servers.subkeys():
            rows.append({"source": "Servers", "server": s.name,
                         "username_hint": value_text(s, "UsernameHint"),
                         "key_last_written": dt_to_iso(s.last_written)})
    return rows


@plugin("network-drives", "Mapped network drives (MRU + persistent)", (NTUSER,))
def network_drives(hive: RegistryHive):
    rows = []
    mru = _cv(hive, "Explorer\\Map Network Drive MRU")
    if mru:
        for v in mru.values():
            if v.name not in ("MRUList", "(default)"):
                rows.append({"source": "MRU", "path": to_text(v.data)})
    net = hive.get("Network")
    if net:
        for d in net.subkeys():
            rows.append({"source": "persistent", "drive": d.name,
                         "remote_path": value_text(d, "RemotePath"),
                         "username": value_text(d, "UserName")})
    return rows


@plugin("office-mru", "Microsoft Office recent files and places", (NTUSER,))
def office_mru(hive: RegistryHive):
    office = first_key(hive, "Software\\Microsoft\\Office")
    if not office:
        return []
    rows = []
    for ver in office.subkeys():
        if not ver.name.replace(".", "").isdigit():
            continue
        for app in ver.subkeys():
            for mru_name in ("File MRU", "Place MRU"):
                mk = subkey(app, "User MRU")
                candidates = []
                if mk:
                    for identity in mk.subkeys():
                        candidates.append(subkey(identity, mru_name))
                candidates.append(subkey(app, mru_name))
                for mru in filter(None, candidates):
                    for v in mru.values():
                        if not v.name.lower().startswith("item"):
                            continue
                        text = to_text(v.data)
                        rows.append({"app": app.name, "kind": mru_name,
                                     "entry": _office_mru_path(text)})
    return rows


def _office_mru_path(text: str) -> str:
    # format: [F00000000][Txxxxxxxxxxxxxxxx][O00000000]*path
    if "*" in text:
        return text.split("*", 1)[1]
    return text


@plugin("feature-usage", "Explorer FeatureUsage - taskbar / app focus counts",
        (NTUSER,))
def feature_usage(hive: RegistryHive):
    base = _cv(hive, "Explorer\\FeatureUsage")
    if not base:
        return []
    rows = []
    for sub in base.subkeys():
        for v in sub.values():
            if v.name == "(default)":
                continue
            rows.append({"category": sub.name, "target": v.name,
                         "count": u32(v.data)})
    return rows


@plugin("sysinternals", "Sysinternals tools whose EULA was accepted (usage)",
        (NTUSER,))
def sysinternals(hive: RegistryHive):
    k = first_key(hive, "Software\\Sysinternals")
    if not k:
        return []
    rows = []
    for tool in k.subkeys():
        rows.append({"tool": tool.name,
                     "eula_accepted": value_text(tool, "EulaAccepted"),
                     "key_last_written": dt_to_iso(tool.last_written)})
    return rows


@plugin("uninstall-user", "Per-user installed programs (Uninstall keys)", (NTUSER,))
def uninstall_user(hive: RegistryHive):
    rows = []
    for b in _CV:
        k = hive.get(f"{b}\\Uninstall")
        if not k:
            continue
        for app in k.subkeys():
            d = {v.name.lower(): to_text(v.data) for v in app.values()}
            rows.append({"key": app.name,
                         "display_name": d.get("displayname", ""),
                         "version": d.get("displayversion", ""),
                         "publisher": d.get("publisher", ""),
                         "install_date": d.get("installdate", ""),
                         "key_last_written": dt_to_iso(app.last_written)})
    return rows
