"""Enumerate SAM local accounts: RID, username, and the raw V value.

Usernames come from ``Users\\Names\\<username>`` - each such key's
default value has no real data, but its declared *type* integer is
overloaded to hold the account's RID directly (a well-known SAM quirk:
``type & 0xFFFF == RID``). This avoids needing to decode the V value's
own uncertain username field at all.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UserRecord:
    rid: int
    username: str
    v_value: bytes


def _rid_to_username(users_key) -> dict[int, str]:
    names = None
    for sub in users_key.subkeys():
        if sub.name.lower() == "names":
            names = sub
            break
    out: dict[int, str] = {}
    if names is None:
        return out
    for user_key in names.subkeys():
        for v in user_key.values():
            rid = v.data_type & 0xFFFF
            if rid:
                out[rid] = user_key.name
                break
    return out


def list_users(sam_hive) -> list[UserRecord]:
    account = sam_hive.get("SAM\\Domains\\Account")
    if account is None:
        account = sam_hive.get("Domains\\Account")
    if account is None:
        return []

    users_key = None
    for sub in account.subkeys():
        if sub.name.lower() == "users":
            users_key = sub
            break
    if users_key is None:
        return []
    usernames = _rid_to_username(users_key)

    out = []
    for rid_key in users_key.subkeys():
        if rid_key.name.lower() == "names":
            continue
        try:
            rid = int(rid_key.name, 16)
        except ValueError:
            continue
        v_bytes = b""
        for v in rid_key.values():
            if v.name.lower() == "v":
                v_bytes = v.raw_data if isinstance(v.raw_data, (bytes,
                                                                bytearray)) \
                    else b""
                break
        out.append(UserRecord(rid, usernames.get(rid, ""), bytes(v_bytes)))
    return out


def get_f_value(sam_hive) -> bytes:
    account = sam_hive.get("SAM\\Domains\\Account")
    if account is None:
        account = sam_hive.get("Domains\\Account")
    if account is None:
        return b""
    for v in account.values():
        if v.name.lower() == "f":
            return v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) \
                else b""
    return b""
