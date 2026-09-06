"""Pull the AppCompatCache value out of a SYSTEM hive (or take a raw blob)."""

from __future__ import annotations

from pathlib import Path

from windows_shimcache.hive import RegistryHive
from windows_shimcache.shimcache import ShimCacheError, ShimEntry, parse

_KEY_TAIL = "Control\\Session Manager\\AppCompatCache"
_ALT_TAIL = "Control\\Session Manager\\AppCompatibility"


def _control_sets(hive: RegistryHive):
    root = hive.root()
    for sub in root.subkeys():
        name = sub.name
        if name.lower() in ("currentcontrolset", "controlset001", "controlset002",
                            "controlset003"):
            yield name


def from_hive_bytes(data: bytes) -> list[ShimEntry]:
    hive = RegistryHive(data)
    entries: list[ShimEntry] = []
    seen_blobs: set[bytes] = set()
    for cs in _control_sets(hive):
        for tail in (_KEY_TAIL, _ALT_TAIL):
            key = hive.get(f"{cs}\\{tail}")
            if key is None:
                continue
            for v in key.values():
                if v.name.lower() not in ("appcompatcache", ""):
                    continue
                blob = v.raw_data if isinstance(v.raw_data, (bytes, bytearray)) \
                    else b""
                if not blob or bytes(blob) in seen_blobs:
                    continue
                seen_blobs.add(bytes(blob))
                try:
                    entries.extend(parse(bytes(blob), control_set=cs))
                except ShimCacheError:
                    continue
    return entries


def from_hive_file(path) -> list[ShimEntry]:
    return from_hive_bytes(Path(path).read_bytes())


def from_blob_file(path) -> list[ShimEntry]:
    return parse(Path(path).read_bytes())


def looks_like_hive(data: bytes) -> bool:
    return data[:4] == b"regf"
