from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_utc(ticks: int) -> datetime | None:
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


def iso_utc(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class VolumeInfo:
    device_path: str = ""
    serial_number: int = 0
    creation_time: datetime | None = None

    @property
    def serial_hex(self) -> str:
        return f"{self.serial_number:08X}" if self.serial_number else ""


@dataclass
class PrefetchFile:
    source: str
    format_version: int = 0
    executable: str = ""
    prefetch_hash: str = ""
    run_count: int = 0
    run_times: list[datetime] = field(default_factory=list)
    volumes: list[VolumeInfo] = field(default_factory=list)
    referenced_files: list[str] = field(default_factory=list)
    directory_strings: list[str] = field(default_factory=list)
    is_compressed: bool = False
    decompressor: str = ""
    warnings: list[str] = field(default_factory=list)
    parse_error: str = ""

    @property
    def last_run(self) -> datetime | None:
        return self.run_times[0] if self.run_times else None

    @property
    def referenced_file_count(self) -> int:
        return len(self.referenced_files)

    def summary_row(self) -> dict:
        row = {
            "executable": self.executable,
            "run_count": self.run_count,
            "last_run_utc": iso_utc(self.last_run),
            "version": self.format_version,
            "prefetch_hash": self.prefetch_hash,
            "referenced_files": self.referenced_file_count,
            "volume_count": len(self.volumes),
        }
        for i in range(8):
            dt = self.run_times[i] if i < len(self.run_times) else None
            row[f"run_time_{i + 1}_utc"] = iso_utc(dt)
        row["volume_devices"] = " | ".join(v.device_path for v in self.volumes)
        row["volume_serials"] = " | ".join(v.serial_hex for v in self.volumes)
        row["volume_created_utc"] = " | ".join(
            iso_utc(v.creation_time) for v in self.volumes
        )
        row["compressed"] = "yes" if self.is_compressed else "no"
        row["decompressor"] = self.decompressor
        row["source"] = self.source
        row["warnings"] = "; ".join(self.warnings)
        row["parse_error"] = self.parse_error
        return row

    def to_json(self) -> dict:
        return {
            "source": self.source,
            "executable": self.executable,
            "prefetch_hash": self.prefetch_hash,
            "format_version": self.format_version,
            "run_count": self.run_count,
            "run_times_utc": [iso_utc(t) for t in self.run_times],
            "volumes": [
                {
                    "device_path": v.device_path,
                    "serial_number": v.serial_hex,
                    "creation_time_utc": iso_utc(v.creation_time),
                }
                for v in self.volumes
            ],
            "referenced_files": list(self.referenced_files),
            "directory_strings": list(self.directory_strings),
            "compressed": self.is_compressed,
            "decompressor": self.decompressor,
            "warnings": list(self.warnings),
            "parse_error": self.parse_error,
        }


SUMMARY_COLUMNS = list(
    PrefetchFile(source="").summary_row()
)
