"""Plugins for the SAM hive - local account information."""

from __future__ import annotations

import struct

from windows_registry.hive import RegistryHive
from windows_registry.plugins._base import (
    ACB_FLAGS,
    SAM,
    dt_to_iso,
    ft_to_iso,
    plugin,
    subkey,
    values_dict,
)

__all__ = ["sam_users", "sam_groups"]

_WELL_KNOWN_RIDS = {500: "Administrator", 501: "Guest", 502: "krbtgt",
                    503: "DefaultAccount", 504: "WDAGUtilityAccount"}


def _ft64(raw: bytes, off: int) -> int:
    if len(raw) >= off + 8:
        lo, hi = struct.unpack_from("<II", raw, off)
        return (hi << 32) | lo
    return 0


def _v_string(v: bytes, index: int) -> str:
    """Read one variable-length string from a SAM 'V' value.

    The V value opens with an array of 17 (offset, length, unknown) triples;
    strings live at 0xCC + offset.
    """
    base = 0xCC
    off = struct.unpack_from("<I", v, 4 + index * 12)[0] + base
    length = struct.unpack_from("<I", v, 8 + index * 12)[0]
    if off + length > len(v) or length <= 0:
        return ""
    return v[off:off + length].decode("utf-16-le", "replace")


@plugin("sam-users", "Local user accounts - last logon, password age, flags",
        (SAM,))
def sam_users(hive: RegistryHive):
    users = hive.get("SAM\\Domains\\Account\\Users") or \
        hive.get("Domains\\Account\\Users")
    if not users:
        return []
    rows = []
    for rid_key in users.subkeys():
        try:
            rid = int(rid_key.name, 16)
        except ValueError:
            continue
        d = values_dict(rid_key)
        f = d["F"].raw_data if "F" in d and isinstance(
            d["F"].raw_data, (bytes, bytearray)) else b""
        v = d["V"].raw_data if "V" in d and isinstance(
            d["V"].raw_data, (bytes, bytearray)) else b""

        username = _v_string(v, 1) if len(v) >= 0xCC else ""
        fullname = _v_string(v, 2) if len(v) >= 0xCC else ""
        comment = _v_string(v, 3) if len(v) >= 0xCC else ""

        last_logon = _ft64(f, 8)
        last_logoff = _ft64(f, 16)
        pwd_last_set = _ft64(f, 24)
        acct_expires = _ft64(f, 32)
        last_bad_pwd = _ft64(f, 40)
        rid_from_f = struct.unpack_from("<I", f, 48)[0] if len(f) >= 52 else rid
        acb = struct.unpack_from("<H", f, 56)[0] if len(f) >= 58 else 0
        bad_count = struct.unpack_from("<H", f, 64)[0] if len(f) >= 66 else 0
        logon_count = struct.unpack_from("<H", f, 66)[0] if len(f) >= 68 else 0

        rows.append({
            "rid": rid,
            "username": username or _WELL_KNOWN_RIDS.get(rid, ""),
            "full_name": fullname,
            "comment": comment,
            "flags": " | ".join(n for b, n in ACB_FLAGS.items() if acb & b),
            "disabled": "yes" if acb & 0x0001 else "no",
            "logon_count": logon_count,
            "failed_logins": bad_count,
            "last_logon_utc": ft_to_iso(last_logon),
            "last_password_set_utc": ft_to_iso(pwd_last_set),
            "last_incorrect_password_utc": ft_to_iso(last_bad_pwd),
            "account_expires_utc": (ft_to_iso(acct_expires)
                                    if acct_expires < 0x7FFFFFFFFFFFFFFF else "never"),
            "key_last_written": dt_to_iso(rid_key.last_written),
        })
    rows.sort(key=lambda r: r["rid"])
    return rows


@plugin("sam-groups", "Local groups and their members", (SAM,))
def sam_groups(hive: RegistryHive):
    aliases = hive.get("SAM\\Domains\\Builtin\\Aliases") or \
        hive.get("Domains\\Builtin\\Aliases")
    if not aliases:
        return []
    names = subkey(aliases, "Names")
    name_by_rid = {}
    if names:
        for nk in names.subkeys():
            dv = values_dict(nk).get("(default)")
            # the (default) value's *type* field holds the alias RID
            if dv is not None:
                name_by_rid[dv.data_type] = nk.name
    rows = []
    for g in aliases.subkeys():
        if g.name in ("Names", "Members"):
            continue
        d = values_dict(g)
        c = d.get("C")
        members = 0
        try:
            rid = int(g.name, 16)
        except ValueError:
            rid = None
        if c and isinstance(c.raw_data, (bytes, bytearray)) and len(c.raw_data) >= 0x34:
            members = struct.unpack_from("<I", c.raw_data, 0x30)[0]
        rows.append({"alias_rid": g.name,
                     "group_name": name_by_rid.get(rid, ""),
                     "member_count": members,
                     "key_last_written": dt_to_iso(g.last_written)})
    return rows
