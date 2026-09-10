"""Common read-only image interface."""

from __future__ import annotations

import abc


class ImageError(Exception):
    pass


class Image(abc.ABC):
    """A seekable, read-only view of a disk image's raw bytes."""

    format_name: str = "image"
    sector_size: int = 512

    @property
    @abc.abstractmethod
    def size(self) -> int:
        """Logical size of the disk in bytes."""

    @abc.abstractmethod
    def read(self, offset: int, length: int) -> bytes:
        """Return *length* bytes starting at *offset* (zero-filled past EOF)."""

    def close(self) -> None:
        pass

    # -- convenience -------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def stream(self, offset: int = 0, length: int | None = None,
               chunk: int = 1 << 20):
        """Yield the image (or a slice) in chunks."""
        end = self.size if length is None else min(self.size, offset + length)
        pos = offset
        while pos < end:
            n = min(chunk, end - pos)
            yield self.read(pos, n)
            pos += n


class SliceImage(Image):
    """A byte-range view of another :class:`Image` (e.g. one partition)."""

    format_name = "slice"

    def __init__(self, parent: Image, offset: int, length: int, label: str = ""):
        self._parent = parent
        self._off = offset
        self._len = length
        self.label = label
        self.sector_size = parent.sector_size

    @property
    def size(self) -> int:
        return self._len

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ImageError("negative offset")
        if offset >= self._len:
            return b""
        length = min(length, self._len - offset)
        return self._parent.read(self._off + offset, length)

    def close(self) -> None:  # do not close the parent
        pass


def zero_pad(data: bytes, length: int) -> bytes:
    return data + b"\x00" * (length - len(data)) if len(data) < length else data
