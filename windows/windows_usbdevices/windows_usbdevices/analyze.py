"""Discover the hives + setupapi log under a path and correlate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from windows_usbdevices import registry as _reg
from windows_usbdevices import setupapi as _sa


@dataclass
class Result:
    devices: list = field(default_factory=list)
    inputs: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    have_system: bool = False
    have_software: bool = False
    have_setupapi: bool = False


_SYSTEM = ("Windows/System32/config/SYSTEM", "System32/config/SYSTEM",
           "config/SYSTEM", "SYSTEM")
_SOFTWARE = ("Windows/System32/config/SOFTWARE", "System32/config/SOFTWARE",
             "config/SOFTWARE", "SOFTWARE")
_SETUPAPI = ("Windows/INF/setupapi.dev.log", "INF/setupapi.dev.log",
             "Windows/inf/setupapi.dev.log", "setupapi.dev.log")


def _find(root: Path, rels) -> Path | None:
    for r in rels:
        c = root / r
        if c.is_file():
            return c
    return None


def _flag(d) -> list[str]:
    out = []
    connects = [t for t in (d.first_install, d.install, d.last_arrival)
                if t]
    if d.serial_synthetic:
        out.append("device reports no unique serial (Windows synthesised one "
                   "with a '&0' suffix)")
    if d.first_install and d.last_arrival and \
            d.first_install[:16] == d.last_arrival[:16]:
        out.append("connected only once (first install == last arrival)")
    for t in connects:
        try:
            hr = datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S").hour
            wd = datetime.strptime(t[:10], "%Y-%m-%d").weekday()
            if hr < 7 or hr >= 20 or wd >= 5:
                out.append(f"connected outside business hours ({t})")
                break
        except ValueError:
            pass
    if not d.drive_letters and not d.volume_guids and \
            (d.first_install or d.install):
        out.append("device installed but never mounted to a drive letter / "
                   "volume in MountedDevices")
    return out


def analyze(paths, known_good: set[str] | None = None) -> Result:
    res = Result()
    for path in paths:
        root = Path(path)
        if root.is_file():
            files = {"system": root} if root.name.upper() == "SYSTEM" else \
                {"software": root} if root.name.upper() == "SOFTWARE" else {}
        else:
            files = {}
        sysh = files.get("system") or _find(root, _SYSTEM)
        softh = files.get("software") or _find(root, _SOFTWARE)
        sapi = _find(root, _SETUPAPI) if not root.is_file() else None

        devices: dict = {}
        if sysh is not None:
            res.have_system = True
            res.inputs.append(str(sysh))
            try:
                devices, _mm = _reg.from_system_hive(sysh.read_bytes())
            except OSError as e:
                res.errors.append(f"{sysh}: {e}")
        if softh is not None and devices:
            res.have_software = True
            res.inputs.append(str(softh))
            try:
                _reg.from_software_hive(softh.read_bytes(), devices)
            except OSError as e:
                res.errors.append(f"{softh}: {e}")
        if sapi is not None:
            res.have_setupapi = True
            res.inputs.append(str(sapi))
            try:
                fs = _sa.first_seen(sapi.read_text("utf-8", errors="replace"))
                for serial, ts in fs.items():
                    for d in devices.values():
                        if d.serial.startswith(serial) or serial in d.serial:
                            d.setupapi_first_seen = ts
            except OSError as e:
                res.errors.append(f"{sapi}: {e}")

        for d in devices.values():
            d.notable = _flag(d)
            if known_good:
                key = f"{d.vendor} {d.product} {d.friendly_name} " \
                      f"{d.serial}".lower()
                if not any(g.lower().strip() in key for g in known_good
                           if g.strip()):
                    d.notable.append("device is not on the --known-good list")
            res.devices.append(d)

    res.devices.sort(key=lambda d: (d.row()["first_connected"] or "",
                                    d.vendor, d.product))
    return res
