"""Enumerate local physical disks / volumes (best effort, per OS)."""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
from pathlib import Path


def _si(n: int) -> str:
    f = float(n)
    for u in ("B", "KB", "MB", "GB", "TB", "PB"):
        if f < 1000 or u == "PB":
            return f"{f:.1f} {u}"
        f /= 1000
    return f"{n} B"


def list_disks() -> list[dict]:
    if os.name == "nt":
        return _windows()
    system = os.uname().sysname if hasattr(os, "uname") else ""
    if system == "Linux":
        return _linux()
    if system == "Darwin":
        return _macos()
    return []


def _linux() -> list[dict]:
    out = []
    block = Path("/sys/block")
    if not block.is_dir():
        return out
    for dev in sorted(block.iterdir()):
        name = dev.name
        if name.startswith(("loop", "ram", "dm-", "zram")):
            continue
        try:
            sectors = int((dev / "size").read_text())
        except (OSError, ValueError):
            continue
        model = _read(dev / "device/model") or _read(dev / "device/name")
        removable = _read(dev / "removable") == "1"
        rot = _read(dev / "queue/rotational")
        parts = [p.name for p in sorted(dev.iterdir())
                 if p.name.startswith(name) and (dev / p.name / "partition").exists()]
        out.append({
            "path": f"/dev/{name}", "size": sectors * 512,
            "size_h": _si(sectors * 512), "model": model,
            "removable": removable,
            "type": "HDD" if rot == "1" else "SSD/flash" if rot == "0" else "",
            "partitions": [f"/dev/{p}" for p in parts],
        })
    return out


def _read(p: Path) -> str:
    try:
        return p.read_text().strip()
    except OSError:
        return ""


def _macos() -> list[dict]:
    try:
        raw = subprocess.run(["diskutil", "list", "-plist", "physical"],
                             capture_output=True, timeout=15).stdout
        data = plistlib.loads(raw)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for disk in data.get("AllDisksAndPartitions", []):
        ident = disk.get("DeviceIdentifier", "")
        size = disk.get("Size", 0)
        out.append({
            "path": f"/dev/{ident}", "size": size, "size_h": _si(size),
            "model": disk.get("MediaName") or disk.get("VolumeName", ""),
            "removable": False, "type": "",
            "partitions": [f"/dev/{p.get('DeviceIdentifier','')}"
                           for p in disk.get("Partitions", [])],
        })
    return out


_WMIC_RE = re.compile(r"^(?P<caption>.+?)\s+(?P<id>\\\\\.\\PHYSICALDRIVE\d+)\s+"
                      r"(?P<size>\d+)\s*$", re.IGNORECASE)


def _windows() -> list[dict]:
    out = _windows_powershell()
    if out:
        return out
    try:
        raw = subprocess.run(
            ["wmic", "diskdrive", "get", "Caption,DeviceID,Size", "/format:csv"],
            capture_output=True, text=True, timeout=15).stdout
    except Exception:  # noqa: BLE001
        return out
    for line in raw.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 4 and parts[2].upper().startswith("\\\\.\\PHYSICALDRIVE"):
            try:
                size = int(parts[3])
            except ValueError:
                continue
            out.append({"path": parts[2], "size": size, "size_h": _si(size),
                        "model": parts[1], "removable": False, "type": "",
                        "partitions": []})
    return out


def _windows_powershell() -> list[dict]:
    ps = ("Get-CimInstance Win32_DiskDrive | ForEach-Object { "
          "'{0}|{1}|{2}|{3}' -f $_.DeviceID,$_.Model,$_.Size,$_.MediaType }")
    try:
        raw = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:  # noqa: BLE001
        return []
    out = []
    for line in raw.splitlines():
        f = line.strip().split("|")
        if len(f) < 3 or not f[0].upper().startswith("\\\\.\\PHYSICALDRIVE"):
            continue
        try:
            size = int(f[2])
        except ValueError:
            size = 0
        out.append({"path": f[0], "size": size, "size_h": _si(size),
                    "model": f[1], "removable": "removable" in (f[3:] or [""])[0].lower(),
                    "type": (f[3] if len(f) > 3 else ""), "partitions": []})
    return out
