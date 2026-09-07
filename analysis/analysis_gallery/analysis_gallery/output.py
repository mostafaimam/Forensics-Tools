"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = [
    "path", "category", "format", "width", "height", "megapixels",
    "size", "sha256", "datetime_original", "make", "model", "lens",
    "iso", "f_number", "exposure", "focal_length", "orientation",
    "software", "gps_lat", "gps_lon", "gps_altitude", "gps_timestamp",
    "duration_s", "has_exif", "has_thumbnail", "phash", "phash_group",
    "notes",
]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(mf) -> dict:
    return {
        "path": mf.path,
        "category": mf.category,
        "format": mf.format,
        "width": mf.width or "",
        "height": mf.height or "",
        "megapixels": mf.megapixels or "",
        "size": mf.size,
        "sha256": mf.sha256,
        "datetime_original": mf.datetime_original,
        "make": mf.make,
        "model": mf.model,
        "lens": mf.lens,
        "iso": mf.iso,
        "f_number": mf.f_number,
        "exposure": mf.exposure,
        "focal_length": mf.focal_length,
        "orientation": mf.orientation,
        "software": mf.software,
        "gps_lat": "" if mf.gps_lat is None else mf.gps_lat,
        "gps_lon": "" if mf.gps_lon is None else mf.gps_lon,
        "gps_altitude": "" if mf.gps_altitude is None else mf.gps_altitude,
        "gps_timestamp": mf.gps_timestamp,
        "duration_s": mf.duration_s or "",
        "has_exif": "yes" if mf.has_exif else "no",
        "has_thumbnail": "yes" if mf.has_thumbnail else "no",
        "phash": mf.phash,
        "phash_group": mf.phash_group or "",
        "notes": mf.notes,
    }


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows: list[dict], path: Path) -> None:
    Path(path).write_text(json.dumps(rows, indent=2, default=str),
                          encoding="utf-8")


def render_table(rows: list[dict]) -> str:
    cols = ["category", "format", "width", "height", "datetime_original",
            "make", "model", "gps_lat", "gps_lon", "phash_group", "path"]
    widths = {c: len(c) for c in cols}
    disp = []
    for r in rows:
        d = {c: _short(r.get(c, ""), c) for c in cols}
        disp.append(d)
        for c in cols:
            widths[c] = max(widths[c], len(d[c]))
    out = io.StringIO()
    out.write("  ".join(c.ljust(widths[c]) for c in cols) + "\n")
    out.write("  ".join("-" * widths[c] for c in cols) + "\n")
    for d in disp:
        out.write("  ".join(d[c].ljust(widths[c]) for c in cols) + "\n")
    return out.getvalue()


def _short(v, col: str) -> str:
    s = "" if v is None else str(v)
    if col == "path":
        return s if len(s) <= 60 else "..." + s[-57:]
    if col in ("make", "model") and len(s) > 16:
        return s[:15] + "…"
    return s
