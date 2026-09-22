"""A single LevelDB key/value record recovered from a .log or .ldb file."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Record:
    source: str
    kind: str            # log | sstable
    sequence: int
    deleted: bool
    key: bytes
    value: bytes
