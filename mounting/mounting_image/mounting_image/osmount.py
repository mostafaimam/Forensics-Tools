"""Attach a materialised image to the OS as a read-only drive / volume.

* **Windows** - ``Mount-DiskImage -Access ReadOnly`` on a fixed VHD; a real
  read-only drive letter (which the caller may choose) appears in Explorer.
* **macOS** - ``hdiutil attach -readonly`` on a raw image.
* **Linux** - ``losetup --read-only --partscan`` + ``mount -o ro``.

All three use only tools that ship with the OS.
"""

from __future__ import annotations

import json
import os
import platform
import plistlib
import shutil
import string
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

_REGISTRY = Path(
    os.environ.get("MOUNTING_IMAGE_STATE",
                   Path.home() / ".local/share/mounting_image/drives.json"))


class OsMountError(Exception):
    pass


@dataclass
class MountResult:
    backend: str                      # windows | macos | linux
    image_file: str                   # the vhd / raw that is attached
    handle: str = ""                  # disk number / loop dev / hdiutil dev
    volumes: list = field(default_factory=list)   # [{name, access, size}]
    temp_image: bool = False


# ---------------------------------------------------------------- Windows
def _ps(script: str, timeout: int = 120) -> str:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise OsMountError("powershell not found")
    r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command",
                        script], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip() or f"powershell exit {r.returncode}"
        if "privilege" in msg.lower() or "elevat" in msg.lower():
            raise OsMountError(
                "Mount-DiskImage needs an elevated session - run "
                "mounting_image (or its terminal) as Administrator")
        raise OsMountError(msg)
    return r.stdout


def free_drive_letters() -> list[str]:
    used = set()
    try:
        out = _ps("(Get-PSDrive -PSProvider FileSystem).Name -join ','")
        used = {x.strip().upper() for x in out.split(",") if x.strip()}
    except OsMountError:
        pass
    return [c for c in string.ascii_uppercase[3:]        # D..Z
            if c not in used]


def mount_windows(vhd_path: str, letter: str | None = None,
                  partition: int | None = None,
                  temp: bool = False) -> MountResult:
    p = str(Path(vhd_path))
    letter = (letter or "").rstrip(":").upper() or None
    script = f"""
$ErrorActionPreference='Stop'
$img = Mount-DiskImage -ImagePath '{p}' -Access ReadOnly -StorageType VHD -PassThru
$disk = $img | Get-DiskImage | Get-Disk
$parts = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
    Where-Object {{ $_.DriveLetter -or $_.Size -gt 1MB }}
"""
    if letter:
        want = f"$_.PartitionNumber -eq {partition}" if partition \
            else "$_.DriveLetter"
        script += f"""
$tgt = $parts | Where-Object {{ {want} }} | Select-Object -First 1
if (-not $tgt) {{ $tgt = $parts | Sort-Object Size -Descending | Select-Object -First 1 }}
if ($tgt) {{ try {{ Set-Partition -DiskNumber $disk.Number -PartitionNumber $tgt.PartitionNumber -NewDriveLetter '{letter}' }} catch {{}} }}
$parts = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
"""
    script += """
$out = [ordered]@{ disk = $disk.Number; volumes = @() }
foreach ($pt in $parts) {
    $out.volumes += [ordered]@{
        partition = $pt.PartitionNumber
        letter    = if ($pt.DriveLetter) { "$($pt.DriveLetter):" } else { "" }
        size      = $pt.Size
    }
}
$out | ConvertTo-Json -Depth 4 -Compress
"""
    data = json.loads(_ps(script) or "{}")
    vols = data.get("volumes") or []
    if isinstance(vols, dict):
        vols = [vols]
    return MountResult(backend="windows", image_file=p,
                       handle=str(data.get("disk", "")),
                       volumes=[{"name": v.get("letter") or f"part{v['partition']}",
                                 "access": "ro", "size": v.get("size", 0)}
                                for v in vols],
                       temp_image=temp)


def unmount_windows(vhd_path: str) -> None:
    _ps(f"Dismount-DiskImage -ImagePath '{Path(vhd_path)}' | Out-Null")


# ---------------------------------------------------------------- macOS
def mount_macos(raw_path: str, temp: bool = False) -> MountResult:
    exe = shutil.which("hdiutil")
    if not exe:
        raise OsMountError("hdiutil not found")
    r = subprocess.run(
        [exe, "attach", "-readonly", "-nobrowse", "-plist",
         "-imagekey", "diskimage-class=CRawDiskImage", str(raw_path)],
        capture_output=True, timeout=120)
    if r.returncode != 0:
        raise OsMountError(r.stderr.decode("utf-8", "replace").strip())
    plist = plistlib.loads(r.stdout)
    entities = plist.get("system-entities", [])
    dev = next((e["dev-entry"] for e in entities
                if e.get("dev-entry", "").count("/") == 2), "")
    vols = [{"name": e.get("mount-point") or e.get("dev-entry"),
             "access": "ro", "size": 0}
            for e in entities if e.get("mount-point") or e.get("volume-kind")]
    return MountResult(backend="macos", image_file=str(raw_path), handle=dev,
                       volumes=vols or [{"name": dev, "access": "ro"}],
                       temp_image=temp)


def unmount_macos(device: str) -> None:
    exe = shutil.which("hdiutil")
    if exe:
        subprocess.run([exe, "detach", device], capture_output=True, timeout=60)


# ---------------------------------------------------------------- Linux
def mount_linux(raw_path: str, mountpoint: str | None, *, fstype: str | None,
                partition: int = 1, temp: bool = False) -> MountResult:
    losetup = shutil.which("losetup")
    if not losetup:
        raise OsMountError("losetup not found")
    r = subprocess.run([losetup, "--find", "--show", "--read-only",
                        "--partscan", str(raw_path)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise OsMountError(r.stderr.strip())
    loop = r.stdout.strip()
    res = MountResult(backend="linux", image_file=str(raw_path), handle=loop,
                      temp_image=temp)
    if mountpoint:
        Path(mountpoint).mkdir(parents=True, exist_ok=True)
        node = f"{loop}p{partition}" if Path(f"{loop}p{partition}").exists() \
            else loop
        opts = "ro,noload" if (fstype or "").startswith("ext") else "ro"
        cmd = ["mount", "-o", opts]
        if fstype:
            cmd += ["-t", fstype]
        cmd += [node, mountpoint]
        m = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if m.returncode != 0:
            subprocess.run([losetup, "-d", loop], capture_output=True)
            raise OsMountError(m.stderr.strip())
        res.volumes = [{"name": mountpoint, "access": "ro", "size": 0}]
    else:
        res.volumes = [{"name": loop, "access": "ro", "size": 0}]
    return res


def unmount_linux(loop: str, mountpoint: str | None) -> None:
    if mountpoint:
        subprocess.run(["umount", mountpoint], capture_output=True, timeout=60)
    if loop:
        subprocess.run([shutil.which("losetup") or "losetup", "-d", loop],
                       capture_output=True, timeout=60)


# ---------------------------------------------------------------- dispatch
def current_backend() -> str:
    return {"Windows": "windows", "Darwin": "macos",
            "Linux": "linux"}.get(platform.system(), "")


def unmount(entry: dict) -> None:
    b = entry.get("backend")
    if b == "windows":
        unmount_windows(entry["image_file"])
    elif b == "macos":
        unmount_macos(entry.get("handle", ""))
    elif b == "linux":
        unmount_linux(entry.get("handle", ""), entry.get("mountpoint"))
    if entry.get("temp_image") and entry.get("image_file"):
        try:
            os.remove(entry["image_file"])
        except OSError:
            pass


# -- session registry -----------------------------------------
def _load() -> list[dict]:
    try:
        return json.loads(_REGISTRY.read_text())
    except (OSError, ValueError):
        return []


def _save(rows: list[dict]) -> None:
    _REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    _REGISTRY.write_text(json.dumps(rows, indent=2))


def register(res: MountResult, source: str, mountpoint: str | None) -> str:
    mid = time.strftime("d%Y%m%d%H%M%S", time.gmtime())
    rows = _load()
    rows.append({"id": mid, "backend": res.backend, "source": source,
                 "image_file": res.image_file, "handle": res.handle,
                 "mountpoint": mountpoint or "",
                 "volumes": res.volumes, "temp_image": res.temp_image,
                 "mounted_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime())})
    _save(rows)
    return mid


def sessions() -> list[dict]:
    return _load()


def deregister(match: str) -> dict | None:
    rows = _load()
    keep, gone = [], None
    for r in rows:
        hit = (gone is None and (
            r.get("id") == match or r.get("image_file") == match
            or match in [v.get("name", "").rstrip(":\\").upper()
                         for v in r.get("volumes", [])]
            or (match or "").rstrip(":\\").upper() in
            [v.get("name", "").rstrip(":\\").upper()
             for v in r.get("volumes", [])]))
        if hit:
            gone = r
        else:
            keep.append(r)
    _save(keep)
    return gone
