"""Open an image, parse the partition table, detect each slice's filesystem."""

from __future__ import annotations

from dataclasses import dataclass, field

from mounting_partitions import fsdetect
from mounting_partitions.formats import ImageError, open_image
from mounting_partitions.partitions import detect as detect_scheme


@dataclass
class Slice:
    index: int
    scheme: str
    start_offset: int
    length: int
    type_label: str
    type_code: str
    name: str
    bootable: bool
    filesystem: str = ""
    note: str = ""

    def row(self) -> dict:
        return {
            "index": self.index, "scheme": self.scheme,
            "start_lba": self.start_offset // 512,
            "start_offset": self.start_offset,
            "end_offset": self.start_offset + self.length,
            "size_bytes": self.length, "size": _hsize(self.length),
            "type": self.type_label, "type_code": self.type_code,
            "label": self.name, "bootable": "yes" if self.bootable else "",
            "filesystem": self.filesystem, "note": self.note,
        }


@dataclass
class Result:
    image_format: str = ""
    image_size: int = 0
    scheme: str = ""
    slices: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _hsize(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"


def analyze(path: str, fmt: str | None = None, *, sector: int = 512) -> Result:
    res = Result()
    try:
        img = open_image(path, fmt)
    except ImageError as e:
        res.errors.append(str(e))
        return res

    from mounting_partitions.formats import sniff
    try:
        res.image_format = fmt or sniff(path)
    except ImageError:
        res.image_format = fmt or "raw"
    res.image_size = img.size

    scheme, parts = detect_scheme(img)
    res.scheme = scheme

    if scheme == "none" or not parts:
        # whole disk may itself be a filesystem
        try:
            head = img.read(0, min(0x11000, img.size))
        except Exception:                        # noqa: BLE001
            head = b""
        fs = fsdetect.detect(head)
        res.slices.append(Slice(
            index=0, scheme="none", start_offset=0, length=img.size,
            type_label="whole disk", type_code="", name="", bootable=False,
            filesystem=fs, note="no partition table"))
        return res

    for p in parts:
        try:
            head = img.read(p.start_offset, min(0x11000,
                                                img.size - p.start_offset))
        except Exception:                        # noqa: BLE001
            head = b""
        fs = fsdetect.detect(head)
        note = ""
        if p.type_label in ("extended", "GPT protective"):
            note = "container / protective entry"
        elif fs == "" and p.length:
            note = "no recognised filesystem in the first sectors"
        res.slices.append(Slice(
            index=p.index, scheme=p.scheme, start_offset=p.start_offset,
            length=p.length, type_label=p.type_label, type_code=p.type_code,
            name=p.name, bootable=p.bootable, filesystem=fs, note=note))

    # gaps / overlaps
    covered = sorted((s.start_offset, s.start_offset + s.length)
                     for s in res.slices
                     if s.type_label not in ("extended", "GPT protective"))
    cursor = sector * (34 if scheme == "gpt" else 1)
    for start, end in covered:
        if start > cursor + sector:
            res.gaps.append((cursor, start, _hsize(start - cursor),
                             "unallocated"))
        elif start < cursor - sector:
            res.gaps.append((start, cursor, _hsize(cursor - start),
                             "OVERLAP"))
        cursor = max(cursor, end)
    tail = img.size - cursor
    if tail > sector * 34:
        res.gaps.append((cursor, img.size, _hsize(tail),
                         "unallocated (tail)"))
    return res
