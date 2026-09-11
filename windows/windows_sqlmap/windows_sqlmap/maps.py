"""Named extraction maps: declarative per-app SQLite profiles."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_TIME_FORMATS = ("unix", "unix_ms", "unix_us", "webkit", "filetime",
                 "iso", "raw")


@dataclass
class SqlMap:
    name: str
    description: str = ""
    match_tables: list = field(default_factory=list)
    query: str = ""
    columns: list = field(default_factory=list)
    time_col: str = ""
    time_format: str = "raw"
    source: str = "built-in"

    @classmethod
    def from_dict(cls, d: dict, source: str = "built-in") -> "SqlMap":
        return cls(name=d["name"], description=d.get("description", ""),
                  match_tables=list(d.get("match_tables", [])),
                  query=d["query"], columns=list(d.get("columns", [])),
                  time_col=d.get("time_col", ""),
                  time_format=d.get("time_format", "raw"), source=source)

    def matches(self, tables: set) -> bool:
        return bool(self.match_tables) and \
            set(t.lower() for t in self.match_tables) <= \
            {t.lower() for t in tables}


_BUILTIN = [
    {
        "name": "skype_main",
        "description": "Skype (classic desktop) main.db chat history",
        "match_tables": ["Messages", "Conversations"],
        "query": "SELECT timestamp, author, from_dispname, dialog_partner, "
                 "chatname, body_xml, type FROM Messages ORDER BY timestamp",
        "columns": ["timestamp", "author", "from_display_name",
                   "dialog_partner", "chat", "body", "msg_type"],
        "time_col": "timestamp", "time_format": "unix",
    },
    {
        "name": "sticky_notes",
        "description": "Windows 10+ Sticky Notes plum.sqlite (schema has "
                       "varied across builds - verify columns present)",
        "match_tables": ["Note"],
        "query": "SELECT Id, Text, CreatedAt, LastModified FROM Note "
                 "ORDER BY LastModified",
        "columns": ["id", "text", "created", "last_modified"],
        "time_col": "last_modified", "time_format": "filetime",
    },
]


def builtin_maps() -> list[SqlMap]:
    return [SqlMap.from_dict(d) for d in _BUILTIN]


def load_map_dir(path: str) -> list[SqlMap]:
    out = []
    for f in sorted(Path(path).glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        try:
            out.append(SqlMap.from_dict(d, source=str(f)))
        except KeyError:
            continue
    return out
