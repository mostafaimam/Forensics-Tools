"""Shared helpers and the plugin registry for windows_registry.

A plugin is a function decorated with :func:`plugin`.  It takes an open
:class:`RegistryHive` and returns ``list[dict]`` (one dict per finding).  Each
plugin declares which hive kinds it applies to so ``--plugin`` (no id) can run
only the relevant ones.
"""

from __future__ import annotations

import codecs
import struct
from datetime import datetime, timedelta, timezone

from windows_registry.hive import Key, RegistryHive, to_text

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# hive kinds
NTUSER = "ntuser"
USRCLASS = "usrclass"
SOFTWARE = "software"
SYSTEM = "system"
SAM = "sam"
SECURITY = "security"
AMCACHE = "amcache"
ANY = "any"

PLUGINS: dict = {}


def plugin(pid: str, description: str, hives: tuple[str, ...] = (ANY,)):
    def deco(fn):
        PLUGINS[pid] = {"fn": fn, "description": description, "hives": hives}
        return fn
    return deco


# -- time / value helpers -------------------------------------------------
def ft_to_iso(ticks: int) -> str:
    if not ticks or ticks <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


def dt_to_iso(dt) -> str:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return ""


def systemtime_to_iso(raw: bytes) -> str:
    if len(raw) < 16:
        return ""
    y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", raw, 0)
    if y == 0:
        return ""
    try:
        return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"
    except ValueError:
        return ""


def rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


def u32(raw, off: int = 0) -> int:
    if isinstance(raw, int):
        return raw
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= off + 4:
        return struct.unpack_from("<I", raw, off)[0]
    return 0


def u64(raw, off: int = 0) -> int:
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= off + 8:
        return struct.unpack_from("<Q", raw, off)[0]
    return 0


# -- key navigation -----------------------------------------------------
def first_key(hive: RegistryHive, *paths: str) -> Key | None:
    for p in paths:
        k = hive.get(p)
        if k is not None:
            return k
    return None


def subkey(key: Key, name: str) -> Key | None:
    if key is None:
        return None
    for s in key.subkeys():
        if s.name.lower() == name.lower():
            return s
    return None


def values_dict(key: Key) -> dict:
    if key is None:
        return {}
    return {v.name: v for v in key.values()}


def value_text(key: Key, name: str, default: str = "") -> str:
    if key is None:
        return default
    for v in key.values():
        if v.name.lower() == name.lower():
            return to_text(v.data)
    return default


def control_sets(hive: RegistryHive):
    root = hive.root()
    names = {s.name.lower(): s.name for s in root.subkeys()}
    for want in ("currentcontrolset", "controlset001", "controlset002",
                 "controlset003"):
        if want in names:
            yield names[want]


def iter_all_values(hive: RegistryHive, under: str):
    key = hive.get(under)
    if key is None:
        return
    for sub in hive.walk(key):
        for v in sub.values():
            if v.name != "(default)":
                yield sub, v


# -- MRUListEx ordering -------------------------------------------------
def mrulistex_order(raw) -> list[int]:
    if not isinstance(raw, (bytes, bytearray)):
        return []
    out = []
    for i in range(0, len(raw) - 3, 4):
        n = struct.unpack_from("<i", raw, i)[0]
        if n == -1:
            break
        out.append(n)
    return out


# -- hive-kind detection ---------------------------------------------
def detect_hive_kind(hive: RegistryHive) -> str:
    name = (hive.base.file_name or "").lower()
    root = {s.name.lower() for s in hive.root().subkeys()}
    if "ntuser.dat" in name or ({"software", "appevents"} <= root):
        return NTUSER
    if "usrclass" in name or "local settings" in root:
        return USRCLASS
    if "select" in root and any(c.startswith("controlset") for c in root):
        return SYSTEM
    if "sam" in root and len(root) <= 2:
        return SAM
    if "policy" in root and len(root) <= 3:
        return SECURITY
    if {"microsoft", "classes"} <= root or "wow6432node" in root:
        return SOFTWARE
    if "root" in root:
        rr = hive.get("Root")
        if rr and any(s.name.lower().startswith(("inventoryapplication", "file",
                                                 "programs"))
                      for s in rr.subkeys()):
            return AMCACHE
    return ANY


ACB_FLAGS = {
    0x0001: "disabled", 0x0002: "homedir-required", 0x0004: "pwd-not-required",
    0x0008: "temp-duplicate", 0x0010: "normal", 0x0020: "mns-logon",
    0x0040: "domain-trust", 0x0080: "workstation-trust", 0x0100: "server-trust",
    0x0200: "pwd-no-expire", 0x0400: "auto-locked",
}
