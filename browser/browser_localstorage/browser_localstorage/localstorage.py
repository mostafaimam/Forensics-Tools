"""Chromium's Local Storage key/value schema, layered on the raw LevelDB
engine.

Chromium keys each stored value as ``_`` + origin + ``\\x00`` + the
page's own JS key (a convention stable since Local Storage moved onto
LevelDB, but internal and undocumented - not a published spec). Values
carry a 1-byte encoding tag: ``0`` = UTF-16LE, ``1`` = Latin-1. Both are
applied best-effort here; a row that doesn't match the expected shape
still comes through with its raw key/value bytes so nothing is silently
dropped.
"""

from __future__ import annotations

from dataclasses import dataclass

_DATA_PREFIX = b"_"


@dataclass
class Entry:
    origin: str
    key: str
    value: str
    matched_schema: bool


def _decode_text(raw: bytes) -> str:
    if not raw:
        return ""
    tag = raw[0]
    body = raw[1:]
    try:
        if tag == 0:
            return body.decode("utf-16-le")
        if tag == 1:
            return body.decode("latin-1")
    except UnicodeDecodeError:
        pass
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.hex()


def decode(key: bytes, value: bytes) -> Entry:
    if key.startswith(_DATA_PREFIX) and b"\x00" in key[1:]:
        rest = key[1:]
        nul = rest.index(b"\x00")
        origin_b, key_b = rest[:nul], rest[nul + 1:]
        try:
            origin = origin_b.decode("utf-8")
        except UnicodeDecodeError:
            origin = origin_b.decode("latin-1")
        try:
            js_key = key_b.decode("utf-8")
        except UnicodeDecodeError:
            js_key = _decode_text(key_b)
        return Entry(origin, js_key, _decode_text(value), True)
    return Entry("", key.decode("latin-1"), _decode_text(value), False)
