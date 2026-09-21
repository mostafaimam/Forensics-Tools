"""Tie boot-key derivation, the LSA key, and each secret's decrypt together."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_lsasecrets.bootkey import BootKeyError, derive_bootkey
from memory_lsasecrets.hive import RegistryHive
from memory_lsasecrets.lsakey import LsaSecretError, decrypt_secret, \
    derive_lsa_key
from memory_lsasecrets.secrets_hive import get_polek_list, list_secrets

COLUMNS = ["name", "value_text", "value_hex", "reversible", "notable"]

_REVERSIBLE_PREFIXES = ("_sc_",)
_NOTABLE_NAMES = ("defaultpassword", "dpapi_system")


def _decode_text(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        text = raw.decode("utf-16-le").rstrip("\x00")
        if text and all(c.isprintable() or c in "\r\n\t" for c in text):
            return text
    except UnicodeDecodeError:
        pass
    try:
        text = raw.decode("utf-8").rstrip("\x00")
        if text and all(c.isprintable() or c in "\r\n\t" for c in text):
            return text
    except UnicodeDecodeError:
        pass
    return ""


def _classify(name: str) -> tuple[bool, str]:
    low = name.lower()
    reversible = any(low.startswith(p) for p in _REVERSIBLE_PREFIXES)
    notable = "service-account-password" if reversible else (
        "sensitive-secret" if low in _NOTABLE_NAMES else "")
    return reversible, notable


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _load_hive(path: str) -> RegistryHive:
    with open(path, "rb") as fh:
        return RegistryHive(fh.read())


def dump(system_path: str, security_path: str) -> Result:
    res = Result()
    try:
        system_hive = _load_hive(system_path)
    except OSError as e:
        res.warnings.append(f"could not read {system_path}: {e}")
        return res
    try:
        security_hive = _load_hive(security_path)
    except OSError as e:
        res.warnings.append(f"could not read {security_path}: {e}")
        return res

    try:
        bootkey = derive_bootkey(system_hive)
    except BootKeyError as e:
        res.warnings.append(f"boot key: {e}")
        return res

    polek = get_polek_list(security_hive)
    if not polek:
        res.warnings.append("SECURITY\\Policy\\PolEKList not found "
                            "(legacy pre-Vista SECURITY hives are out of "
                            "scope for v0.1 - see README)")
        return res
    try:
        lsa_key = derive_lsa_key(bootkey, polek)
    except LsaSecretError as e:
        res.warnings.append(f"LSA key: {e}")
        return res

    secrets = list_secrets(security_hive)
    if not secrets:
        res.warnings.append("no secrets found under "
                            "SECURITY\\Policy\\Secrets")
    for s in secrets:
        try:
            plain = decrypt_secret(lsa_key, s.curr_val)
        except LsaSecretError as e:
            res.warnings.append(f"{s.name}: {e}")
            continue
        reversible, notable = _classify(s.name)
        res.rows.append({
            "name": s.name,
            "value_text": _decode_text(plain),
            "value_hex": plain.hex(),
            "reversible": reversible,
            "notable": notable,
        })
    return res
