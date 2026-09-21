"""Locate iOS backup folders and read their top-level metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mobile_iosbackup.plists import load_file


@dataclass
class BackupInfo:
    root: Path
    udid: str
    is_encrypted: bool | None
    device_name: str
    product_type: str
    product_version: str
    serial_number: str
    last_backup_date: str
    raw_manifest: dict = field(default_factory=dict)
    raw_info: dict = field(default_factory=dict)


def _get(d: dict, *keys, default=""):
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return d[k]
    return default


def is_backup_dir(path: Path) -> bool:
    return path.is_dir() and (path / "Manifest.db").is_file()


def find_backups(root: str) -> list[Path]:
    r = Path(root)
    if is_backup_dir(r):
        return [r]
    out = []
    if r.is_dir():
        for p in sorted(r.rglob("Manifest.db")):
            out.append(p.parent)
    return out


def load_backup(path: Path) -> BackupInfo:
    manifest = {}
    info = {}
    mp = path / "Manifest.plist"
    if mp.is_file():
        try:
            manifest = load_file(mp) or {}
        except Exception:  # noqa: BLE001
            manifest = {}
    ip = path / "Info.plist"
    if ip.is_file():
        try:
            info = load_file(ip) or {}
        except Exception:  # noqa: BLE001
            info = {}

    is_encrypted = manifest.get("IsEncrypted") if isinstance(manifest, dict) \
        else None
    last_backup = _get(info, "Last Backup Date", "LastBackupDate")
    return BackupInfo(
        root=path,
        udid=str(_get(info, "Unique Identifier", "UDID", default=path.name)),
        is_encrypted=is_encrypted,
        device_name=str(_get(info, "Device Name", "DeviceName")),
        product_type=str(_get(info, "Product Type", "ProductType")),
        product_version=str(_get(info, "Product Version", "ProductVersion")),
        serial_number=str(_get(info, "Serial Number", "SerialNumber")),
        last_backup_date=str(last_backup) if last_backup else "",
        raw_manifest=manifest if isinstance(manifest, dict) else {},
        raw_info=info if isinstance(info, dict) else {},
    )
