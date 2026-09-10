"""Walk bam / dam UserSettings in a SYSTEM hive."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from windows_bam.hive import RegistryHive

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_SID_RE = re.compile(r"^S-\d-\d+(-\d+)*$")
_DEVICE_RE = re.compile(r"^\\Device\\HarddiskVolume(\d+)\\", re.I)


def _ft(v: bytes) -> str:
    if len(v) < 8:
        return ""
    ticks = struct.unpack_from("<Q", v, 0)[0]
    if ticks <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class Entry:
    sid: str
    raw_path: str
    path: str            # \Device\... rewritten to <volN>\...
    last_run: str
    moderator: str       # bam | dam
    control_set: str
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {"sid": self.sid, "path": self.path, "raw_path": self.raw_path,
                "last_run": self.last_run, "moderator": self.moderator,
                "control_set": self.control_set,
                "notable": ";".join(self.notable)}


@dataclass
class Result:
    entries: list = field(default_factory=list)
    sids: set = field(default_factory=set)
    errors: list = field(default_factory=list)


def _norm_path(p: str) -> str:
    m = _DEVICE_RE.match(p)
    if m:
        return f"<vol{m.group(1)}>\\" + p[m.end():]
    return p


def _control_sets(hive: RegistryHive):
    root = hive.root()
    for sub in root.subkeys():
        n = sub.name.lower()
        if n in ("currentcontrolset", "controlset001", "controlset002",
                 "controlset003"):
            yield sub.name


def _usersettings_key(hive: RegistryHive, cs: str, mod: str):
    for tail in (f"{cs}\\Services\\{mod}\\State\\UserSettings",
                 f"{cs}\\Services\\{mod}\\UserSettings"):
        k = hive.get(tail)
        if k is not None:
            return k
    return None


def parse(data: bytes) -> Result:
    res = Result()
    try:
        hive = RegistryHive(data)
    except Exception as e:                        # noqa: BLE001 vendored
        res.errors.append(f"hive parse failed: {e}")
        return res

    for cs in _control_sets(hive):
        for mod in ("bam", "dam"):
            us = _usersettings_key(hive, cs, mod)
            if us is None:
                continue
            for sid_key in us.subkeys():
                sid = sid_key.name
                if not _SID_RE.match(sid):
                    continue
                res.sids.add(sid)
                for v in sid_key.values():
                    name = v.name
                    if name.lower() in ("version", "sequencenumber", ""):
                        continue
                    raw = v.raw_data if isinstance(
                        v.raw_data, (bytes, bytearray)) else b""
                    ts = _ft(bytes(raw))
                    if not ts and "\\" not in name:
                        continue
                    res.entries.append(Entry(
                        sid=sid, raw_path=name, path=_norm_path(name),
                        last_run=ts, moderator=mod,
                        control_set=cs))
    res.entries.sort(key=lambda e: (e.last_run or "", e.path))
    return res
