"""Tie image loading, the VACB-chain walk, and optional extraction
together."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from memory_dumpfiles.loader import MemoryImage, MemoryImageError
from memory_dumpfiles.pagemap import Pml4, find_kernel_dtb
from memory_dumpfiles.vacbscan import read_cached_view, scan

COLUMNS = ["name", "file_object_phys", "vacb_va", "file_offset",
          "view_size", "recovered", "source"]

_UNSAFE = re.compile(r'[\\/:*?"<>|]')


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def scan_image(image_path: str, *, dump_dir: str | None = None) -> Result:
    res = Result()
    try:
        img = MemoryImage(image_path)
    except (MemoryImageError, OSError) as e:
        res.warnings.append(f"{image_path}: {e}")
        return res

    with img:
        dtb = find_kernel_dtb(img)
        if dtb is None:
            res.warnings.append("could not locate the kernel directory "
                                "-table base (x64 Windows images only "
                                "in v0.1)")
            return res
        pml4 = Pml4(img, dtb)
        hits = scan(img)

        out_dir = Path(dump_dir) if dump_dir else None
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)

        any_vacb = False
        for h in hits:
            if not h.vacbs:
                res.rows.append({
                    "name": h.name, "file_object_phys": hex(
                        h.file_object_phys), "vacb_va": "",
                    "file_offset": "", "view_size": "", "recovered": "no "
                    "resident cache view found", "source": image_path})
                continue
            any_vacb = True
            for v in h.vacbs:
                try:
                    view = read_cached_view(pml4, v)
                except Exception as e:  # noqa: BLE001
                    res.rows.append({"name": h.name, "file_object_phys":
                                    hex(h.file_object_phys), "vacb_va":
                                    hex(v.va), "file_offset": v.file_offset,
                                    "view_size": "", "recovered": f"read "
                                    f"failed: {e}", "source": image_path})
                    continue
                recovered = f"{len(view)} bytes"
                if out_dir:
                    safe = _UNSAFE.sub("_", h.name) or "unnamed"
                    dest = out_dir / f"{safe}.{v.file_offset:#x}.bin"
                    dest.write_bytes(view)
                    recovered += f" -> {dest}"
                res.rows.append({"name": h.name, "file_object_phys":
                                hex(h.file_object_phys), "vacb_va":
                                hex(v.va), "file_offset": v.file_offset,
                                "view_size": len(view), "recovered":
                                recovered, "source": image_path})

        if not hits:
            res.warnings.append("no _FILE_OBJECT structures found (pool "
                                "tag scan)")
        elif not any_vacb:
            res.warnings.append("_FILE_OBJECT structures found, but no "
                                "resident SharedCacheMap/VACB chain "
                                "self-verified for any of them - files "
                                "may not be cache-mapped, or this "
                                "project's offset-window scan didn't "
                                "cover the right range for this build")
    return res
