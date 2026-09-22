"""Tie image loading and the candidate-table scan together."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_ssdt.loader import MemoryImage, MemoryImageError
from memory_ssdt.ssdtscan import scan

COLUMNS = ["phys_offset", "entry_count", "cluster_lo", "cluster_hi",
          "outlier_count", "outlier_sample", "source"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def scan_image(image_path: str, *, min_entries: int | None = None) -> \
        Result:
    res = Result()
    try:
        with MemoryImage(image_path) as img:
            candidates = scan(img)
    except (MemoryImageError, OSError) as e:
        res.warnings.append(f"{image_path}: {e}")
        return res

    for c in candidates:
        if min_entries and len(c.entries) < min_entries:
            continue
        sample = ", ".join(f"[{i}]={p:#x}" for i, p in c.outliers[:5])
        res.rows.append({
            "phys_offset": hex(c.phys_offset),
            "entry_count": len(c.entries),
            "cluster_lo": hex(c.cluster_lo),
            "cluster_hi": hex(c.cluster_hi),
            "outlier_count": len(c.outliers),
            "outlier_sample": sample,
            "source": image_path,
        })
    if not res.rows:
        res.warnings.append(
            "no candidate function-pointer table found - expected and "
            "correct on many modern x64 Windows images (see the "
            "README's Confidence & Validation section), not "
            "necessarily a sign of a problem")
    return res
