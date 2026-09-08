"""A small built-in OUI table + MAC helpers (no bundled IEEE database)."""

from __future__ import annotations

# Common prefixes only - enough to recognise virtualisation and a few big
# vendors.  A full OUI lookup would need the IEEE registry as a data file.
_OUI = {
    "000569": "VMware", "000c29": "VMware", "005056": "VMware",
    "001c14": "VMware",
    "080027": "VirtualBox", "0a0027": "VirtualBox",
    "00155d": "Microsoft Hyper-V", "001dd8": "Microsoft",
    "525400": "QEMU/KVM", "000f4b": "Oracle",
    "001c42": "Parallels",
    "00163e": "Xen",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "001b63": "Apple", "3c0754": "Apple", "a4c361": "Apple", "f0d1a9": "Apple",
    "001a2b": "Cisco", "00000c": "Cisco", "0018ba": "Cisco",
    "001560": "HP", "001e0b": "HP", "3417eb": "Dell", "b8ca3a": "Dell",
    "d4be d9": "Dell",
    "001a11": "Google", "3c5ab4": "Google",
    "fcfbfb": "Cisco Meraki",
    "0050f2": "Microsoft", "0003ff": "Microsoft",
}


def norm(mac: str) -> str:
    h = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(h) != 12:
        return mac.lower().strip()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def vendor(mac: str) -> str:
    h = "".join(c for c in mac.lower() if c in "0123456789abcdef")[:6]
    return _OUI.get(h, "")


def is_local(mac: str) -> bool:
    """The locally-administered bit (bit 1 of the first octet)."""
    h = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(h) < 2:
        return False
    try:
        return bool(int(h[:2], 16) & 0x02)
    except ValueError:
        return False


def is_multicast(mac: str) -> bool:
    h = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(h) < 2:
        return False
    try:
        return bool(int(h[:2], 16) & 0x01)
    except ValueError:
        return False
