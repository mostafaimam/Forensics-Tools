"""Output writers: manifest CSV, error CSV, run summary.

Pain points addressed:

* CSV injection: any cell beginning with ``= + - @`` or a control char is
  prefixed with a single quote so spreadsheet apps do not evaluate it.
* Encoding: CSV is written UTF-8 **with BOM** so Excel opens non-ASCII
  filenames correctly; line terminator is ``\r\n`` per RFC 4180.
* Timestamps: ISO-8601 UTC with microseconds, ``Z`` suffix, never local time.
"""

from __future__ import annotations

import csv
import io
import json
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from acquisition_collect import __version__

MANIFEST_NAME = "acquisition_collect_manifest.csv"
ERRORS_NAME = "acquisition_collect_errors.csv"
SUMMARY_NAME = "acquisition_collect_summary.txt"
RUNINFO_NAME = "acquisition_collect_runinfo.json"

_MANIFEST_COLUMNS = [
    "target_id", "target_name", "category", "source_path", "output_path",
    "size_bytes", "backend", "locked_fallback",
    "md5", "sha1", "sha256",
    "created_utc", "modified_utc", "accessed_utc", "changed_utc",
    "collected_utc",
]
_ERROR_COLUMNS = ["target_id", "source_path", "stage", "error"]


def iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sanitise(value: object) -> str:
    s = "" if value is None else str(value)
    if s and (s[0] in ("=", "+", "-", "@") or s[0] in ("\t", "\r", "\n")):
        return "'" + s
    return s


@dataclass
class ManifestRow:
    target_id: str
    target_name: str
    category: str
    source_path: str
    output_path: str
    size_bytes: int
    backend: str
    locked_fallback: bool
    hashes: dict
    created_utc: datetime | None
    modified_utc: datetime | None
    accessed_utc: datetime | None
    changed_utc: datetime | None
    collected_utc: datetime

    def as_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "target_name": self.target_name,
            "category": self.category,
            "source_path": self.source_path,
            "output_path": self.output_path,
            "size_bytes": self.size_bytes,
            "backend": self.backend,
            "locked_fallback": "yes" if self.locked_fallback else "no",
            "md5": self.hashes.get("md5", ""),
            "sha1": self.hashes.get("sha1", ""),
            "sha256": self.hashes.get("sha256", ""),
            "created_utc": iso(self.created_utc),
            "modified_utc": iso(self.modified_utc),
            "accessed_utc": iso(self.accessed_utc),
            "changed_utc": iso(self.changed_utc),
            "collected_utc": iso(self.collected_utc),
        }


@dataclass
class RunStats:
    files_collected: int = 0
    bytes_collected: int = 0
    errors: int = 0
    targets_matched: int = 0
    locked_fallbacks: int = 0
    started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished: datetime | None = None


class Report:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._man_fh = (out_dir / MANIFEST_NAME).open(
            "w", encoding="utf-8-sig", newline=""
        )
        self._man = csv.DictWriter(
            self._man_fh, fieldnames=_MANIFEST_COLUMNS, dialect="excel"
        )
        self._man.writeheader()
        self._err_fh = (out_dir / ERRORS_NAME).open(
            "w", encoding="utf-8-sig", newline=""
        )
        self._err = csv.DictWriter(
            self._err_fh, fieldnames=_ERROR_COLUMNS, dialect="excel"
        )
        self._err.writeheader()
        self.stats = RunStats()
        self._finalised = False

    def add_file(self, row: ManifestRow) -> None:
        self._man.writerow({k: _sanitise(v) for k, v in row.as_dict().items()})
        self._man_fh.flush()
        self.stats.files_collected += 1
        self.stats.bytes_collected += row.size_bytes
        if row.locked_fallback:
            self.stats.locked_fallbacks += 1

    def add_error(self, target_id: str, source_path: str, stage: str,
                  error: str) -> None:
        self._err.writerow({
            "target_id": _sanitise(target_id),
            "source_path": _sanitise(source_path),
            "stage": _sanitise(stage),
            "error": _sanitise(error),
        })
        self._err_fh.flush()
        self.stats.errors += 1

    def write_runinfo(self, info: dict) -> None:
        (self.out_dir / RUNINFO_NAME).write_text(
            json.dumps(info, indent=2, sort_keys=True), encoding="utf-8"
        )

    def finalise(self, extra: dict | None = None) -> str:
        if self._finalised:
            return (self.out_dir / SUMMARY_NAME).read_text(encoding="utf-8")
        self._finalised = True
        self.stats.finished = datetime.now(timezone.utc)
        self._man_fh.close()
        self._err_fh.close()
        dur = (self.stats.finished - self.stats.started).total_seconds()
        lines = [
            "acquisition_collect collection summary",
            "=" * 40,
            f"Version         : {__version__}",
            f"Host            : {platform.node()}  ({platform.platform()})",
            f"Started (UTC)    : {iso(self.stats.started)}",
            f"Finished (UTC)   : {iso(self.stats.finished)}",
            f"Duration        : {dur:.1f}s",
            f"Targets matched : {self.stats.targets_matched}",
            f"Files collected : {self.stats.files_collected}",
            f"Bytes collected : {self.stats.bytes_collected:,}",
            f"Locked fallbacks: {self.stats.locked_fallbacks}",
            f"Errors          : {self.stats.errors}",
        ]
        for k, v in (extra or {}).items():
            lines.append(f"{k:<16}: {v}")
        text = "\n".join(lines) + "\n"
        (self.out_dir / SUMMARY_NAME).write_text(text, encoding="utf-8")
        return text
