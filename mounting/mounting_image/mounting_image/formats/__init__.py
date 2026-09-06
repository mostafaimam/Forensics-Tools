"""Container-format sniffing and dispatch."""

from __future__ import annotations

from pathlib import Path

from mounting_image.formats.base import Image, ImageError, SliceImage
from mounting_image.formats.ewf import EWFImage
from mounting_image.formats.raw import RawImage
from mounting_image.formats.vhd import VHDImage
from mounting_image.formats.vhdx import VHDXImage, is_vhdx
from mounting_image.formats.vmdk import VMDKImage

__all__ = ["Image", "ImageError", "SliceImage", "open_image", "sniff"]

_EWF_SIGS = (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00",
             b"EVF2\x0d\x0a\x81\x00")


def sniff(path: str | Path) -> str:
    p = Path(path)
    try:
        with p.open("rb") as fh:
            head = fh.read(2048)
    except OSError as e:
        raise ImageError(str(e)) from None
    if head[:8] in _EWF_SIGS or head[:4] == b"EVF2":
        return "ewf"
    if is_vhdx(p):
        return "vhdx"
    if head[:4] in (b"KDMV", b"COWD"):
        return "vmdk"
    if b"# Disk DescriptorFile" in head or b'createType="' in head:
        return "vmdk"
    if head[:8] == b"conectix":
        return "vhd"
    # VHD keeps its identifying footer in the last 512 bytes
    try:
        with p.open("rb") as fh:
            fh.seek(-512, 2)
            if fh.read(8) == b"conectix":
                return "vhd"
    except OSError:
        pass
    suf = p.suffix.lower()
    if suf in (".e01", ".s01", ".l01", ".ex01"):
        return "ewf"
    if suf == ".vhd":
        return "vhd"
    if suf == ".vmdk":
        return "vmdk"
    return "raw"


_OPENERS = {"ewf": EWFImage, "vhd": VHDImage, "vhdx": VHDXImage,
            "vmdk": VMDKImage, "raw": RawImage}


def open_image(path: str | Path, fmt: str | None = None) -> Image:
    fmt = fmt or sniff(path)
    opener = _OPENERS.get(fmt)
    if opener is None:
        raise ImageError(f"unknown format: {fmt}")
    return opener(path)
