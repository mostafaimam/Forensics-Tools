"""Build a real .ab archive for tests."""

from __future__ import annotations

import io
import tarfile
import zlib
from pathlib import Path


def _build_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 1735689600  # 2025-01-01
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build_ab(path: Path, *, files: dict[str, bytes] | None = None,
            compressed: bool = True, version: int = 5,
            encryption: str = "none") -> None:
    files = files or {
        "apps/com.example.app/_manifest": b"manifest data",
        "apps/com.example.app/f/notes.txt": b"hello from the app",
        "apps/com.example.app/db/app.db": b"sqlite data here",
        "apps/com.example.app/sp/prefs.xml": b"<map/>",
        "shared/0/Pictures/photo.jpg": b"\xff\xd8\xff fake jpeg",
    }
    tar_bytes = _build_tar(files)
    payload = zlib.compress(tar_bytes) if compressed else tar_bytes

    header = b"ANDROID BACKUP\n"
    header += f"{version}\n".encode()
    header += (b"1\n" if compressed else b"0\n")
    header += encryption.encode() + b"\n"
    path.write_bytes(header + payload)


def build_encrypted_ab(path: Path) -> None:
    header = (b"ANDROID BACKUP\n5\n1\nAES-256\n"
             b"deadbeef\n" b"cafebabe\n" b"10000\n" b"1234abcd\n"
             b"aabbccdd\n")
    path.write_bytes(header + b"\x00" * 100)


def build_bad_magic(path: Path) -> None:
    path.write_bytes(b"NOT AN ANDROID BACKUP\n5\n0\nnone\n")
