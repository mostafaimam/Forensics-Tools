from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import BinaryIO, Iterator


class ReadError(Exception):
    """Raised when a source file cannot be opened or fully read."""


@dataclass
class FileTimes:
    """All timestamps are timezone-aware UTC."""

    modified: datetime | None = None
    accessed: datetime | None = None
    changed: datetime | None = None  # ctime / MFT entry-modified
    created: datetime | None = None  # birth time where available

    @staticmethod
    def _utc(ts: float | None) -> datetime | None:
        if ts is None or ts <= 0:
            return None
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    @classmethod
    def from_stat(cls, st: os.stat_result) -> "FileTimes":
        birth = getattr(st, "st_birthtime", None)
        return cls(
            modified=cls._utc(st.st_mtime),
            accessed=cls._utc(st.st_atime),
            changed=cls._utc(st.st_ctime),
            created=cls._utc(birth),
        )


@dataclass
class CollectedStream:
    """A source file opened for reading, plus its metadata."""

    source_path: str
    size: int
    times: FileTimes
    handle: BinaryIO
    backend: str
    locked_fallback: bool = False
    extra: dict = field(default_factory=dict)

    def chunks(self, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        try:
            while True:
                data = self.handle.read(chunk_size)
                if not data:
                    break
                yield data
        finally:
            self.close()

    def close(self) -> None:
        try:
            self.handle.close()
        except OSError:
            pass


class Reader:
    """Interface every backend implements."""

    name = "base"

    def __enter__(self) -> "Reader":
        self.setup()
        return self

    def __exit__(self, *exc) -> None:
        self.teardown()

    def setup(self) -> None:  # pragma: no cover - default no-op
        pass

    def teardown(self) -> None:  # pragma: no cover - default no-op
        pass

    def resolve(self, path: str) -> str:
        """Map a live-system path into this backend's namespace."""
        return path

    def stat(self, path: str) -> os.stat_result:
        raise NotImplementedError

    def open(self, path: str) -> CollectedStream:
        raise NotImplementedError
