"""Plugins for Amcache.hve (program-execution / driver inventory)."""

from __future__ import annotations

from windows_registry.hive import RegistryHive, to_text
from windows_registry.plugins._base import (
    AMCACHE,
    dt_to_iso,
    ft_to_iso,
    plugin,
    value_text,
    values_dict,
)


@plugin("amcache-files", "InventoryApplicationFile / File entries - path, sha1, "
        "compile time", (AMCACHE,))
def amcache_files(hive: RegistryHive):
    root = hive.get("Root\\InventoryApplicationFile")
    rows = []
    if root:
        for e in root.subkeys():
            d = {v.name.lower(): to_text(v.data) for v in e.values()}
            rows.append({
                "path": d.get("lowercaselongpath", d.get("longpathhash", "")),
                "name": d.get("name", ""),
                "sha1": (d.get("filepath", "") or d.get("fileid", ""))[-40:],
                "publisher": d.get("publisher", ""),
                "product": d.get("productname", ""),
                "version": d.get("version", ""),
                "size": d.get("size", ""),
                "linkdate_utc": d.get("linkdate", ""),
                "key_last_written": dt_to_iso(e.last_written),
            })
        return rows
    legacy = hive.get("Root\\File")
    if legacy:
        for vol in legacy.subkeys():
            for e in vol.subkeys():
                d = values_dict(e)
                rows.append({
                    "path": value_text(e, "15"),
                    "sha1": value_text(e, "101")[-40:],
                    "publisher": value_text(e, "0"),
                    "product": value_text(e, "6"),
                    "version": value_text(e, "5"),
                    "size": value_text(e, "6"),
                    "compiled_utc": ft_to_iso(_int(d.get("f"))),
                    "key_last_written": dt_to_iso(e.last_written),
                })
    return rows


@plugin("amcache-programs", "InventoryApplication - installed programs", (AMCACHE,))
def amcache_programs(hive: RegistryHive):
    root = hive.get("Root\\InventoryApplication")
    if not root:
        return []
    rows = []
    for e in root.subkeys():
        d = {v.name.lower(): to_text(v.data) for v in e.values()}
        rows.append({
            "name": d.get("name", ""),
            "version": d.get("version", ""),
            "publisher": d.get("publisher", ""),
            "install_date": d.get("installdate", ""),
            "source": d.get("source", ""),
            "root_dir": d.get("rootdirpath", ""),
            "uninstall": d.get("uninstallstring", ""),
        })
    return rows


@plugin("amcache-drivers", "InventoryDriverBinary - loaded / installed drivers",
        (AMCACHE,))
def amcache_drivers(hive: RegistryHive):
    root = hive.get("Root\\InventoryDriverBinary")
    if not root:
        return []
    rows = []
    for e in root.subkeys():
        d = {v.name.lower(): to_text(v.data) for v in e.values()}
        rows.append({
            "driver": d.get("driumaname", d.get("drivername", e.name)),
            "inf": d.get("inf", ""),
            "signed": d.get("driversigned", ""),
            "signer": d.get("driversignerinfo", d.get("signer", "")),
            "company": d.get("drivercompany", ""),
            "version": d.get("driverversion", ""),
            "product": d.get("product", ""),
            "last_write_utc": d.get("driverlastwritetime", ""),
            "key_last_written": dt_to_iso(e.last_written),
        })
    return rows


def _int(v):
    try:
        return int(to_text(v.data)) if v is not None else 0
    except (ValueError, AttributeError):
        return 0
