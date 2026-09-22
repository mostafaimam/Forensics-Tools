"""Guess which decoder to try for a blob."""

from __future__ import annotations

_BPLIST_MAGIC = b"bplist00"
_SQLITE_MAGIC = b"SQLite format 3\x00"


def guess_format(data: bytes) -> str:
    if data.startswith(_BPLIST_MAGIC):
        return "plist"
    if data.startswith(_SQLITE_MAGIC):
        return "sqlite"
    head = data.lstrip()
    if head[:1] in (b"<", b"{", b"["):
        return "text"
    return "protobuf"
