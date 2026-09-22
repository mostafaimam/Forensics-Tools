"""Flatten VSS identifier hits and their candidate fields into rows."""

from __future__ import annotations

from dataclasses import dataclass, field

from mounting_vsc.vss import scan

COLUMNS = ["hit_offset", "kind", "field_offset", "value", "source"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(path: str) -> Result:
    res = Result()
    with open(path, "rb") as fh:
        data = fh.read()
    hits = scan(data)
    for h in hits:
        res.rows.append({"hit_offset": h.offset, "kind": "vss_identifier",
                        "field_offset": h.offset,
                        "value": f"header={h.header_hex[:32]}...",
                        "source": path})
        for ft in h.candidate_filetimes:
            res.rows.append({"hit_offset": h.offset, "kind": "filetime",
                            "field_offset": ft["offset"],
                            "value": ft["utc"], "source": path})
        for g in h.candidate_guids:
            res.rows.append({"hit_offset": h.offset, "kind": "guid",
                            "field_offset": g["offset"],
                            "value": g["guid"], "source": path})
    if not hits:
        res.warnings.append(
            "no VSS identifier GUID found - either this volume/image "
            "has no shadow copies, or they're stored somewhere this "
            "byte-level scan didn't cover")
    return res
