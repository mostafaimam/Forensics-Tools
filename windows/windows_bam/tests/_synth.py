"""Build a synthetic SYSTEM hive with a bam / dam UserSettings subtree."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from _hive_synth import HiveBuilder, ft

SID_USER = "S-1-5-21-1111111111-2222222222-3333333333-1001"
SID_SYS = "S-1-5-18"


def _ftblob(dt: datetime) -> bytes:
    return struct.pack("<Q", ft(dt)) + b"\x00" * 16


def build_system_hive() -> bytes:
    b = HiveBuilder()
    t = lambda *a: datetime(*a, tzinfo=timezone.utc)  # noqa: E731

    entries = {
        SID_USER: [
            ("\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
             t(2026, 3, 6, 9, 0)),
            ("\\Device\\HarddiskVolume3\\Users\\victim\\AppData\\Local\\Temp\\"
             "agent.exe", t(2026, 3, 6, 9, 5)),
            ("\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell"
             "\\v1.0\\powershell.exe", t(2026, 3, 6, 9, 6)),
            ("\\Device\\HarddiskVolume3\\Users\\victim\\Downloads\\svchost.exe",
             t(2026, 3, 6, 10, 0)),
        ],
        SID_SYS: [
            ("\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe",
             t(2026, 3, 6, 8, 0)),
        ],
    }

    def sid_key(name, items):
        vals = [b.vk_bin(p, _ftblob(dt)) for p, dt in items]
        vals.append(b.vk_bin("SequenceNumber", struct.pack("<I", len(items))))
        return b.nk(name, values=len(vals), val_list=b.value_list(vals))

    bam_user = sid_key(SID_USER, entries[SID_USER])
    bam_sys = sid_key(SID_SYS, entries[SID_SYS])
    bam_us = b.nk("UserSettings", subkeys=2, sub_list=b.li([bam_user,
                                                           bam_sys]))
    bam_state = b.nk("State", subkeys=1, sub_list=b.li([bam_us]))
    bam = b.nk("bam", subkeys=1, sub_list=b.li([bam_state]))

    dam_user = sid_key(SID_USER, [
        ("\\Device\\HarddiskVolume3\\Program Files\\App\\App.exe",
         datetime(2026, 3, 6, 11, 0, tzinfo=timezone.utc))])
    dam_us = b.nk("UserSettings", subkeys=1, sub_list=b.li([dam_user]))
    dam_state = b.nk("State", subkeys=1, sub_list=b.li([dam_us]))
    dam = b.nk("dam", subkeys=1, sub_list=b.li([dam_state]))

    services = b.nk("Services", subkeys=2, sub_list=b.li([bam, dam]))
    ccs = b.nk("ControlSet001", subkeys=1, sub_list=b.li([services]))
    root = b.nk("ROOT", flags=0x2C, subkeys=1, sub_list=b.li([ccs]))
    return b.build(root)
