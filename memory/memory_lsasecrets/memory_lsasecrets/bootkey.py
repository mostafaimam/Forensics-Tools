"""Derive the SYSTEM hive's "boot key" (aka syskey).

Under ``SYSTEM\\<CurrentControlSet>\\Control\\Lsa`` sit four subkeys -
``JD``, ``Skew1``, ``GBG``, ``Data`` - whose registry *class* strings
(a rarely-used field most tools never read) each hold 8 hex characters.
Concatenated in that order and hex-decoded, the 16 resulting bytes are
run through a fixed permutation to produce the boot key: the same
algorithm every public SAM/LSA-secrets tool has implemented identically
for over two decades.
"""

from __future__ import annotations

_PERMUTE = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
           0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]

_LSA_SUBKEYS = ("JD", "Skew1", "GBG", "Data")


class BootKeyError(ValueError):
    pass


def _current_control_set(hive) -> str:
    key = hive.get("Select")
    if key is not None:
        for v in key.values():
            if v.name.lower() == "current":
                try:
                    return f"ControlSet{int(v.data):03d}"
                except (TypeError, ValueError):
                    pass
    return "ControlSet001"


def derive_bootkey(hive) -> bytes:
    cs = _current_control_set(hive)
    lsa = hive.get(f"{cs}\\Control\\Lsa")
    if lsa is None:
        raise BootKeyError(f"{cs}\\Control\\Lsa not found in this hive")
    by_name = {s.name.lower(): s for s in lsa.subkeys()}
    scrambled_hex = ""
    for name in _LSA_SUBKEYS:
        sub = by_name.get(name.lower())
        if sub is None:
            raise BootKeyError(f"Lsa\\{name} not found")
        scrambled_hex += hive.class_name(sub)
    if len(scrambled_hex) < 32:
        raise BootKeyError("LSA class-name boot-key material is incomplete "
                          f"({len(scrambled_hex)} hex chars, need 32)")
    try:
        scrambled = bytes.fromhex(scrambled_hex[:32])
    except ValueError as e:
        raise BootKeyError(f"boot-key material is not valid hex: {e}") from e
    return bytes(scrambled[i] for i in _PERMUTE)
