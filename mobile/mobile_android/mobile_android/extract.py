"""Decode an unencrypted .ab payload into a tar member inventory."""

from __future__ import annotations

import io
import tarfile
import zlib
from dataclasses import dataclass

from mobile_android.abformat import AbHeader, parse_header


class EncryptedBackupError(ValueError):
    pass


@dataclass
class Entry:
    path: str
    package: str
    category: str        # f | db | sp | r | a | manifest | shared | other
    size: int
    mtime: str
    mode: int
    entry_type: str       # file | directory | symlink | other


def _classify(name: str) -> tuple[str, str]:
    parts = name.split("/")
    if parts and parts[0] == "apps" and len(parts) >= 2:
        package = parts[1]
        category = parts[2] if len(parts) >= 3 else "manifest"
        if category not in ("f", "db", "sp", "r", "a"):
            category = "manifest" if category == "_manifest" else "other"
        return package, category
    if parts and parts[0] == "shared":
        return "", "shared"
    return "", "other"


def _tar_open(payload: bytes) -> tarfile.TarFile:
    return tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")


def open_payload(ab_path: str) -> tuple[bytes, AbHeader]:
    with open(ab_path, "rb") as fh:
        data = fh.read()
    header = parse_header(data)
    if header.encryption != "none":
        raise EncryptedBackupError(
            f"backup is {header.encryption}-encrypted - decrypting an "
            f".ab key-wrapping blob is out of scope for v0.1 (see "
            f"README); supply an unencrypted backup")
    payload = data[header.header_len:]
    if header.compressed:
        payload = zlib.decompress(payload)
    return payload, header


def list_entries(ab_path: str) -> tuple[list[Entry], AbHeader]:
    payload, header = open_payload(ab_path)
    entries = []
    with _tar_open(payload) as tf:
        for m in tf.getmembers():
            package, category = _classify(m.name)
            if m.isdir():
                entry_type = "directory"
            elif m.issym() or m.islnk():
                entry_type = "symlink"
            elif m.isfile():
                entry_type = "file"
            else:
                entry_type = "other"
            entries.append(Entry(
                path=m.name, package=package, category=category,
                size=m.size, mtime=_iso(m.mtime), mode=m.mode,
                entry_type=entry_type))
    return entries, header


def _iso(unix_ts) -> str:
    from datetime import datetime, timezone
    try:
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return ""


def extract_all(ab_path: str, out_dir: str, *, name_filter=None) -> int:
    from pathlib import Path
    payload, _header = open_payload(ab_path)
    n = 0
    with _tar_open(payload) as tf:
        for m in tf.getmembers():
            if name_filter and not name_filter(m.name):
                continue
            if not (m.isfile() or m.isdir()):
                continue
            dest = Path(out_dir) / m.name
            if m.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            dest.write_bytes(src.read())
            n += 1
    return n
