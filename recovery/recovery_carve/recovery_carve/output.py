from __future__ import annotations

import csv
from pathlib import Path

from recovery_carve.scanner import Carving, Source

_COLUMNS = [
    "index", "offset", "length_bytes", "end_offset", "type", "category",
    "extension", "confidence", "truncated", "md5", "sha1", "output_path",
]


def _sanitise(value) -> str:
    s = "" if value is None else str(value)
    if s[:1] in ("=", "+", "-", "@") or s[:1] in ("\t", "\r", "\n"):
        return "'" + s
    return s


class Writer:
    def __init__(self, out_dir: Path, source: Source, write_files: bool) -> None:
        self.out_dir = out_dir
        self.source = source
        self.write_files = write_files
        self.files_dir = out_dir / "carved"
        if write_files:
            self.files_dir.mkdir(parents=True, exist_ok=True)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
        self._fh = (out_dir / "recovery_carve_manifest.csv").open(
            "w", encoding="utf-8-sig", newline="")
        self._csv = csv.DictWriter(self._fh, fieldnames=_COLUMNS, dialect="excel")
        self._csv.writeheader()
        self.count = 0
        self.bytes = 0

    def add(self, c: Carving) -> None:
        self.count += 1
        self.bytes += c.length
        if self.write_files:
            name = f"{self.count:06d}_{c.offset:012x}_{c.signature_id}.{c.ext}"
            dest = self.files_dir / name
            with dest.open("wb") as out:
                remaining = c.length
                pos = c.offset
                while remaining > 0:
                    chunk = self.source.read_at(pos, min(remaining, 4 << 20))
                    if not chunk:
                        break
                    out.write(chunk)
                    pos += len(chunk)
                    remaining -= len(chunk)
            c.output_path = str(dest)
        self._csv.writerow({k: _sanitise(v) for k, v in {
            "index": self.count,
            "offset": c.offset,
            "length_bytes": c.length,
            "end_offset": c.end,
            "type": c.signature_id,
            "category": c.category,
            "extension": c.ext,
            "confidence": c.confidence,
            "truncated": "yes" if c.truncated else "no",
            "md5": c.md5,
            "sha1": c.sha1,
            "output_path": c.output_path,
        }.items()})
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
