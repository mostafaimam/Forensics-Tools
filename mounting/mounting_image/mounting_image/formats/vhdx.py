"""VHDX detection.

Full VHDX read support (region table, BAT, metadata region, log replay) is
not implemented yet.  The signature is recognised so callers can give a
useful message instead of mis-parsing the file.
"""

from __future__ import annotations

from pathlib import Path

from mounting_image.formats.base import Image, ImageError

SIGNATURE = b"vhdxfile"


def is_vhdx(path: str | Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == SIGNATURE
    except OSError:
        return False


class VHDXImage(Image):
    format_name = "vhdx"

    def __init__(self, path: str | Path):
        raise ImageError(
            "VHDX read support is not implemented yet - convert the image "
            "to raw first, or attach it read-only in Windows Disk Management")

    @property
    def size(self) -> int:  # pragma: no cover - constructor always raises
        return 0

    def read(self, offset: int, length: int) -> bytes:  # pragma: no cover
        return b""
