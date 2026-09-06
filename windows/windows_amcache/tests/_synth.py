"""Build a synthetic Amcache.hve (modern and legacy layouts)."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from _hive_synth import HiveBuilder

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def ft(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc) - _FT_EPOCH).total_seconds()
               * 10_000_000)


def _sz(b: HiveBuilder, name: str, s: str) -> int:
    return b.vk(name, _u16(s), 1)                      # REG_SZ


def _dword(b: HiveBuilder, name: str, n: int) -> int:
    return b.vk_resident_dword(name, n & 0xFFFFFFFF)


def _qword(b: HiveBuilder, name: str, n: int) -> int:
    return b.vk(name, struct.pack("<Q", n), 11)        # REG_QWORD


def build_modern_amcache() -> bytes:
    b = HiveBuilder()

    def entry(name, values):
        offs = [fn(b) for fn in values]
        vl = b.value_list(offs)
        return b.nk(name, parent=0, values=len(offs), val_list=vl,
                    when=datetime(2024, 4, 1, 9, 0, tzinfo=timezone.utc))

    f1 = entry("0001abcd", [
        lambda b: _sz(b, "LowerCaseLongPath", r"c:\windows\system32\cmd.exe"),
        lambda b: _sz(b, "Name", "cmd.exe"),
        lambda b: _sz(b, "FileId",
                      "0000da39a3ee5e6b4b0d3255bfef95601890afd80709"[:44]),
        lambda b: _dword(b, "Size", 289792),
        lambda b: _sz(b, "Publisher", "Microsoft Corporation"),
        lambda b: _sz(b, "Version", "10.0.19041.1"),
        lambda b: _sz(b, "ProgramId", "0006abc123"),
    ])
    f2 = entry("0002ef01", [
        lambda b: _sz(b, "LowerCaseLongPath",
                      r"c:\users\a\appdata\local\temp\evil.exe"),
        lambda b: _sz(b, "Name", "evil.exe"),
        lambda b: _sz(b, "FileId",
                      "0000" + "a" * 40),
        lambda b: _dword(b, "Size", 4096),
    ])
    fl = b.lh([f1, f2])
    inv_file = b.nk("InventoryApplicationFile", parent=0, subkeys=2, sub_list=fl)

    p1 = entry("app-guid-1", [
        lambda b: _sz(b, "Name", "7-Zip 23.01"),
        lambda b: _sz(b, "Publisher", "Igor Pavlov"),
        lambda b: _sz(b, "Version", "23.01"),
        lambda b: _sz(b, "RootDirPath", r"c:\program files\7-zip"),
    ])
    pl = b.lh([p1])
    inv_prog = b.nk("InventoryApplication", parent=0, subkeys=1, sub_list=pl)

    d1 = entry("driver-1", [
        lambda b: _sz(b, "DriverName", r"c:\windows\system32\drivers\evil.sys"),
        lambda b: _sz(b, "DriverId", "0000" + "b" * 40),
        lambda b: _sz(b, "DriverCompany", "Unknown"),
        lambda b: _sz(b, "DriverSigned", "0"),
    ])
    dl = b.lh([d1])
    inv_drv = b.nk("InventoryDriverBinary", parent=0, subkeys=1, sub_list=dl)

    root_list = b.lh([inv_file, inv_prog, inv_drv])
    inv_root = b.nk("Root", parent=0, subkeys=3, sub_list=root_list)
    root_top = b.lh([inv_root])
    root = b.nk("ROOT", parent=0, flags=0x2C, subkeys=1, sub_list=root_top)
    return b.build(root)


def build_legacy_amcache() -> bytes:
    b = HiveBuilder()
    vals = [
        _sz(b, "15", r"C:\tools\nc.exe"),
        _sz(b, "0", "Netcat"),
        _sz(b, "6", "12345"),
        _sz(b, "101", "0000" + "c" * 40),
        _qword(b, "17", ft(datetime(2023, 9, 1, tzinfo=timezone.utc))),
    ]
    vl = b.value_list(vals)
    fileid = b.nk("00001111deadbeef", parent=0, values=len(vals), val_list=vl)
    guid_list = b.lh([fileid])
    volume = b.nk("{11111111-2222-3333-4444-555555555555}", parent=0,
                  subkeys=1, sub_list=guid_list)
    vol_list = b.lh([volume])
    file_key = b.nk("File", parent=0, subkeys=1, sub_list=vol_list)
    root_list = b.lh([file_key])
    root = b.nk("ROOT", parent=0, flags=0x2C, subkeys=1, sub_list=root_list)
    return b.build(root)
