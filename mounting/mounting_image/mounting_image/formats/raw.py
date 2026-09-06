"""Raw / dd images, including multi-segment split sets."""

from __future__ import annotations

import re
from pathlib import Path

from mounting_image.formats.base import Image, ImageError

# recognised split-segment suffixes, in the order the segments run
_SPLIT_PATTERNS = [
    re.compile(r"^(?P<stem>.+?)\.(?P<idx>\d{3})$"),          # img.001, img.002
    re.compile(r"^(?P<stem>.+?)\.(?P<idx>[a-z]{2})$"),       # img.aa, img.ab
    re.compile(r"^(?P<stem>.+?)\.(?P<idx>\d{3})\.dd$"),
]


def _segment_key(name: str):
    for rx in _SPLIT_PATTERNS:
        m = rx.match(name)
        if m:
            idx = m.group("idx")
            val = int(idx) if idx.isdigit() else _alpha(idx)
            return m.group("stem"), val
    return None


def _alpha(s: str) -> int:
    v = 0
    for c in s:
        v = v * 26 + (ord(c) - 97)
    return v


class RawImage(Image):
    format_name = "raw"

    def __init__(self, path: str | Path):
        path = Path(path)
        self._segments: list[tuple[int, int, Path]] = []   # (start, size, path)
        paths = self._resolve_segments(path)
        pos = 0
        for p in paths:
            sz = p.stat().st_size
            self._segments.append((pos, sz, p))
            pos += sz
        self._size = pos
        self._fh = {}
        if not self._segments:
            raise ImageError(f"empty image: {path}")

    def _resolve_segments(self, path: Path) -> list[Path]:
        key = _segment_key(path.name)
        if key is None:
            return [path]
        stem, _ = key
        siblings = []
        for sib in path.parent.iterdir():
            k = _segment_key(sib.name)
            if k and k[0] == stem:
                siblings.append((k[1], sib))
        siblings.sort()
        return [p for _, p in siblings]

    @property
    def size(self) -> int:
        return self._size

    @property
    def segment_count(self) -> int:
        return len(self._segments)

    def _handle(self, p: Path):
        fh = self._fh.get(p)
        if fh is None:
            fh = self._fh[p] = p.open("rb")
        return fh

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ImageError("negative offset")
        out = bytearray()
        remaining = length
        pos = offset
        for start, sz, p in self._segments:
            if remaining <= 0:
                break
            if pos >= start + sz:
                continue
            if pos < start:
                break
            local = pos - start
            take = min(remaining, sz - local)
            fh = self._handle(p)
            fh.seek(local)
            chunk = fh.read(take)
            out += chunk
            if len(chunk) < take:            # short read -> stop
                break
            pos += take
            remaining -= take
        if len(out) < length and offset + length <= self._size:
            out += b"\x00" * (length - len(out))
        return bytes(out)

    def close(self) -> None:
        for fh in self._fh.values():
            fh.close()
        self._fh.clear()
