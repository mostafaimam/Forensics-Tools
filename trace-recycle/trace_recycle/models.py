from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# FILETIME epoch: 1601-01-01 UTC, ticks of 100 ns.
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_utc(ticks: int) -> datetime | None:
    """Convert a Windows FILETIME (100 ns since 1601-01-01 UTC) to an aware
    UTC datetime. Returns None for 0 / out-of-range values."""
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


def iso_utc(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class RecycleRecord:
    """One deleted item recovered from a Recycle Bin artefact."""

    source: str                       # artefact file this came from
    source_kind: str                  # "$I" | "INFO2" | "INFO"
    format_version: str               # "1", "2", "INFO2-v5", ...
    original_path: str = ""           # full original path of the deleted file
    original_size: int | None = None  # bytes (logical for $I, physical for INFO2)
    deleted_utc: datetime | None = None
    recycle_id: str = ""              # the <id> shared by $I<id> / $R<id>
    index: int | None = None          # INFO2 record index (the N in Dc<N>)
    drive: str = ""                   # drive letter where available
    sid: str = ""                     # account SID from the parent folder name
    content_present: bool = False     # matching $R file / Dc file found
    content_path: str = ""            # path to that content
    content_is_dir: bool = False
    active: bool = True               # False = slot marked removed (INFO2)
    parse_error: str = ""             # non-empty => this row is an error report
    warnings: list[str] = field(default_factory=list)

    @property
    def deleted_utc_iso(self) -> str:
        return iso_utc(self.deleted_utc)

    def as_row(self) -> dict:
        return {
            "original_path": self.original_path,
            "original_size": "" if self.original_size is None else self.original_size,
            "deleted_utc": self.deleted_utc_iso,
            "drive": self.drive,
            "sid": self.sid,
            "recycle_id": self.recycle_id,
            "index": "" if self.index is None else self.index,
            "content_present": "yes" if self.content_present else "no",
            "content_path": self.content_path,
            "content_is_dir": "yes" if self.content_is_dir else "no",
            "active": "yes" if self.active else "no",
            "source_kind": self.source_kind,
            "format_version": self.format_version,
            "source": self.source,
            "warnings": "; ".join(self.warnings),
            "parse_error": self.parse_error,
        }


ROW_COLUMNS = list(RecycleRecord(source="", source_kind="", format_version="").as_row())
