"""Tie image loading and the callback-array scan together."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_callbacks.callbackscan import scan
from memory_callbacks.loader import MemoryImage, MemoryImageError

COLUMNS = ["phys_offset", "size", "registered_count", "registered_sample",
          "outlier_count", "outlier_sample", "source"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def scan_image(image_path: str) -> Result:
    res = Result()
    try:
        with MemoryImage(image_path) as img:
            candidates = scan(img)
    except (MemoryImageError, OSError) as e:
        res.warnings.append(f"{image_path}: {e}")
        return res

    for c in candidates:
        reg_sample = ", ".join(f"[{i}]={c.entries[i]:#x}"
                               for i in c.non_null_indices[:6])
        out_sample = ", ".join(f"[{i}]={c.entries[i]:#x}"
                               for i in c.outlier_indices[:6])
        res.rows.append({
            "phys_offset": hex(c.phys_offset),
            "size": c.size,
            "registered_count": len(c.non_null_indices),
            "registered_sample": reg_sample,
            "outlier_count": len(c.outlier_indices),
            "outlier_sample": out_sample,
            "source": image_path,
        })
    if not res.rows:
        res.warnings.append(
            "no candidate callback-array found - either none are "
            "registered (a legitimately quiet system), or the "
            "8/64-entry sizes this project scans for don't match this "
            "table's actual size")
    return res
