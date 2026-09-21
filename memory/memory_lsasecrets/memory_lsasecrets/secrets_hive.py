"""Read PolEKList and the Secrets tree out of a SECURITY hive.

Both the key-list and every individual secret live the same way: as a
subkey whose unnamed ("default") value holds the raw encrypted blob -
``Policy\\PolEKList\\(default)`` and ``Policy\\Secrets\\<name>\\CurrVal\\
(default)``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecretRecord:
    name: str
    curr_val: bytes


def _get(hive, path: str):
    key = hive.get(f"SECURITY\\{path}")
    if key is None:
        key = hive.get(path)
    return key


def _find_value(key, name: str) -> bytes:
    for v in key.values():
        if v.name.lower() == name.lower():
            return v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) \
                else b""
    return b""


def get_polek_list(hive) -> bytes:
    """v0.1 supports the modern PolEKList scheme only - see the README."""
    policy = _get(hive, "Policy")
    if policy is None:
        return b""
    for sub in policy.subkeys():
        if sub.name.lower() == "poleklist":
            return _find_value(sub, "(default)")
    return b""


def list_secrets(hive) -> list[SecretRecord]:
    policy = _get(hive, "Policy")
    if policy is None:
        return []
    secrets_key = None
    for sub in policy.subkeys():
        if sub.name.lower() == "secrets":
            secrets_key = sub
            break
    if secrets_key is None:
        return []
    out = []
    for name_key in secrets_key.subkeys():
        curr_val_key = None
        for sub in name_key.subkeys():
            if sub.name.lower() == "currval":
                curr_val_key = sub
                break
        if curr_val_key is None:
            continue
        raw = _find_value(curr_val_key, "(default)")
        if raw:
            out.append(SecretRecord(name_key.name, raw))
    return out
