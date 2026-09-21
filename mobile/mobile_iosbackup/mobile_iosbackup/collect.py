"""Tie backup discovery, Manifest.db, and file-metadata decoding together."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from mobile_iosbackup.backup import find_backups, load_backup
from mobile_iosbackup.dbopen import connect, has_table, query
from mobile_iosbackup.fileentry import decode

COLUMNS = ["udid", "device_name", "product_type", "product_version",
          "domain", "relative_path", "file_id", "file_type", "size",
          "mode_octal", "uid", "gid", "protection_class", "birth",
          "last_modified", "last_status_change", "on_disk",
          "file_id_mismatch"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    backups: list = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _expected_file_id(domain: str, relative_path: str) -> str:
    return hashlib.sha1(f"{domain}-{relative_path}".encode()).hexdigest()


def _on_disk_path(backup_root: Path, file_id: str) -> Path:
    return backup_root / file_id[:2] / file_id


def collect(targets: list[str]) -> Result:
    res = Result()
    roots: list[Path] = []
    for t in targets:
        roots.extend(find_backups(t))
    if not roots:
        res.warnings.append("no iOS backup (Manifest.db) found")
        return res

    for root in roots:
        info = load_backup(root)
        res.backups.append(info)
        if info.is_encrypted:
            res.warnings.append(
                f"{root}: backup is password-encrypted - Manifest.db and "
                f"file contents are unreadable without the backup password "
                f"unwrapping the keybag, which is out of scope for v0.1 "
                f"(see README)")
            continue
        try:
            with connect(root / "Manifest.db") as con:
                if not has_table(con, "Files"):
                    res.warnings.append(f"{root}: Manifest.db has no "
                                        "Files table")
                    continue
                rows = query(con, "SELECT fileID, domain, relativePath, "
                            "file FROM Files")
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"{root}: {e}")
            continue

        for r in rows:
            file_id = r["fileID"]
            domain = r["domain"] or ""
            rel_path = r["relativePath"] or ""
            meta = decode(r["file"]) if r["file"] else None
            expected = _expected_file_id(domain, rel_path)
            on_disk = _on_disk_path(root, file_id).is_file()
            res.rows.append({
                "udid": info.udid, "device_name": info.device_name,
                "product_type": info.product_type,
                "product_version": info.product_version,
                "domain": domain, "relative_path": rel_path,
                "file_id": file_id,
                "file_type": meta.file_type if meta else "",
                "size": meta.size if meta else "",
                "mode_octal": (oct(meta.mode) if meta and meta.mode
                              is not None else ""),
                "uid": meta.uid if meta else "",
                "gid": meta.gid if meta else "",
                "protection_class": meta.protection_class if meta else "",
                "birth": meta.birth if meta else "",
                "last_modified": meta.last_modified if meta else "",
                "last_status_change": meta.last_status_change if meta
                else "",
                "on_disk": on_disk,
                "file_id_mismatch": expected != file_id,
            })
    return res
