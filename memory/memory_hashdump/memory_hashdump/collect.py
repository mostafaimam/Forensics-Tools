"""Tie the SYSTEM boot key, SAM F value, and per-user V values together."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_hashdump.bootkey import BootKeyError, derive_bootkey
from memory_hashdump.hive import RegistryHive
from memory_hashdump.samhash import (SamHashError, compute_hashed_boot_key,
                                     decode_user_hashes, hash_hex,
                                     is_empty_hash)
from memory_hashdump.users import get_f_value, list_users

COLUMNS = ["rid", "username", "lm_hash", "nt_hash", "lm_empty", "nt_empty"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    revision: int | None = None


def _load_hive(path: str) -> RegistryHive:
    with open(path, "rb") as fh:
        return RegistryHive(fh.read())


def dump(system_path: str, sam_path: str) -> Result:
    res = Result()
    try:
        system_hive = _load_hive(system_path)
    except OSError as e:
        res.warnings.append(f"could not read {system_path}: {e}")
        return res
    try:
        sam_hive = _load_hive(sam_path)
    except OSError as e:
        res.warnings.append(f"could not read {sam_path}: {e}")
        return res

    try:
        bootkey = derive_bootkey(system_hive)
    except BootKeyError as e:
        res.warnings.append(f"boot key: {e}")
        return res

    f_value = get_f_value(sam_hive)
    if not f_value:
        res.warnings.append("SAM\\Domains\\Account\\F value not found")
        return res
    try:
        hbk = compute_hashed_boot_key(f_value, bootkey)
    except SamHashError as e:
        res.warnings.append(f"hashed boot key: {e}")
        return res
    res.revision = hbk.revision

    users = list_users(sam_hive)
    if not users:
        res.warnings.append("no user accounts found under "
                            "SAM\\Domains\\Account\\Users")
    for u in users:
        if not u.v_value:
            res.warnings.append(f"RID {u.rid}: no V value")
            continue
        try:
            lm, nt = decode_user_hashes(u.v_value, u.rid, hbk)
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"RID {u.rid}: {e}")
            continue
        res.rows.append({
            "rid": u.rid, "username": u.username,
            "lm_hash": hash_hex(lm), "nt_hash": hash_hex(nt),
            "lm_empty": is_empty_hash(lm, is_nt=False),
            "nt_empty": is_empty_hash(nt, is_nt=True),
        })
    return res
