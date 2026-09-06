from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from trace_timeline.timeparse import iso_utc

COLUMNS = [
    "timestamp_utc", "timestamp_type", "tool", "artifact",
    "host", "user", "description", "source_file", "source_row", "extra",
]


@dataclass
class Event:
    timestamp: datetime
    timestamp_type: str          # e.g. "modified", "execution", "deleted"
    tool: str                    # originating tool / adapter
    description: str
    artifact: str = ""           # artefact category
    host: str = ""
    user: str = ""
    source_file: str = ""
    source_row: int = 0
    extra: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.timestamp, self.timestamp_type, self.tool, self.description)

    def as_row(self) -> dict:
        return {
            "timestamp_utc": iso_utc(self.timestamp),
            "timestamp_type": self.timestamp_type,
            "tool": self.tool,
            "artifact": self.artifact,
            "host": self.host,
            "user": self.user,
            "description": self.description,
            "source_file": self.source_file,
            "source_row": self.source_row,
            "extra": json.dumps(self.extra, sort_keys=True, default=str) if self.extra else "",
        }

    def as_json(self) -> dict:
        row = self.as_row()
        row["extra"] = self.extra
        row["source_row"] = self.source_row
        return row
