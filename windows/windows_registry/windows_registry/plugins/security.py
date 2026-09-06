"""Plugins for the SECURITY hive."""

from __future__ import annotations

import struct

from windows_registry.hive import RegistryHive
from windows_registry.plugins._base import (
    SECURITY,
    dt_to_iso,
    plugin,
    subkey,
)


def _sid(raw: bytes) -> str:
    if not raw or len(raw) < 8:
        return ""
    rev = raw[0]
    count = raw[1]
    auth = int.from_bytes(raw[2:8], "big")
    subs = []
    for i in range(count):
        off = 8 + i * 4
        if off + 4 > len(raw):
            break
        subs.append(str(struct.unpack_from("<I", raw, off)[0]))
    return "-".join(["S", str(rev), str(auth)] + subs)


@plugin("policy-secrets", "LSA secrets present (names only - values are encrypted)",
        (SECURITY,))
def policy_secrets(hive: RegistryHive):
    k = hive.get("Policy\\Secrets")
    if not k:
        return []
    rows = []
    for s in k.subkeys():
        cur = subkey(s, "CurrVal")
        old = subkey(s, "OldVal")
        rows.append({
            "secret": s.name,
            "current_size": len(cur.values()[0].raw_data)
            if cur and cur.values() and isinstance(
                cur.values()[0].raw_data, (bytes, bytearray)) else 0,
            "has_old_value": "yes" if old else "no",
            "updated_utc": _oval_time(subkey(s, "CupdTime")),
            "key_last_written": dt_to_iso(s.last_written),
        })
    return rows


def _oval_time(key):
    if not key:
        return ""
    vs = key.values()
    if vs and isinstance(vs[0].raw_data, (bytes, bytearray)) \
            and len(vs[0].raw_data) >= 8:
        from windows_registry.plugins._base import ft_to_iso
        return ft_to_iso(struct.unpack_from("<Q", vs[0].raw_data, 0)[0])
    return ""


@plugin("policy-accounts", "Accounts granted LSA privileges / rights", (SECURITY,))
def policy_accounts(hive: RegistryHive):
    k = hive.get("Policy\\Accounts")
    if not k:
        return []
    rows = []
    for acc in k.subkeys():
        priv = subkey(acc, "PrivilgeSet") or subkey(acc, "PrivilegeSet")
        rows.append({"sid": acc.name,
                     "has_privilege_set": "yes" if priv else "no",
                     "key_last_written": dt_to_iso(acc.last_written)})
    return rows


@plugin("policy-domain", "Primary domain / machine SID from the SECURITY policy",
        (SECURITY,))
def policy_domain(hive: RegistryHive):
    rows = []
    for name in ("PolAcDmS", "PolPrDmS", "PolDnDDN", "PolPrDmN"):
        k = hive.get(f"Policy\\{name}")
        if not k or not k.values():
            continue
        raw = k.values()[0].raw_data
        if not isinstance(raw, (bytes, bytearray)):
            continue
        if name.endswith(("DmS",)):
            rows.append({"field": name, "value": _sid(bytes(raw))})
        else:
            rows.append({"field": name,
                         "value": bytes(raw).decode("utf-16-le", "ignore").strip("\x00")})
    return rows
