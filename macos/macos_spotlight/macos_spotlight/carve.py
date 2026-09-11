"""Chunked ASCII/UTF-16LE string carving, classified against patterns.py."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from macos_spotlight.patterns import classify

_CHUNK = 8 << 20


@dataclass
class Hit:
    source: str
    offset: int
    encoding: str          # ascii | utf-16le
    text: str
    category: str = ""

    def row(self, hex_offset: bool) -> dict:
        return {
            "source": self.source,
            "offset": f"{self.offset:#x}" if hex_offset else self.offset,
            "encoding": self.encoding,
            "category": self.category,
            "text": self.text,
        }


def _res(min_len: int):
    return {
        "ascii": re.compile(rb"[\x09\x20-\x7e]{%d,}" % min_len),
        "utf-16le": re.compile(rb"(?:[\x09\x20-\x7e]\x00){%d,}" % min_len),
    }


def _decode(enc: str, raw: bytes) -> str:
    if enc == "ascii":
        return raw.decode("ascii", "replace")
    return raw.decode("utf-16-le", "replace")


def iter_strings(path, *, min_len=4, encodings=("ascii", "utf-16le")):
    regexes = {e: r for e, r in _res(min_len).items() if e in encodings}
    overlap = 1 << 16
    with open(path, "rb") as fh:
        carry = b""
        carry_base = 0
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            buf = carry + block
            buf_base = carry_base
            horizon = len(buf) - (overlap if len(block) == _CHUNK else 0)
            for enc, rx in regexes.items():
                for m in rx.finditer(buf):
                    if m.start() >= horizon:
                        continue
                    yield buf_base + m.start(), enc, _decode(enc, m.group(0))
            carry = buf[horizon:]
            carry_base = buf_base + horizon


def scan_file(path, source_label: str, *, min_len=6,
             encodings=("ascii", "utf-16le"), categories=None):
    for offset, enc, text in iter_strings(path, min_len=min_len,
                                          encodings=encodings):
        for cat, matched in classify(text, categories):
            yield Hit(source_label, offset, enc, matched, cat)


def find_stores(target: str) -> list[Path]:
    """Resolve a file or a volume/directory to candidate store files."""
    p = Path(target)
    if p.is_file():
        return [p]
    if not p.is_dir():
        return []
    hits: list[Path] = []
    for name_pat in ("store.db", ".store.db", "store.db.previous",
                     "dbStr-*.map.expected", "*.store.db"):
        hits.extend(p.rglob(name_pat))
    # de-dupe while preserving order
    seen = set()
    out = []
    for h in hits:
        if h not in seen and h.is_file():
            seen.add(h)
            out.append(h)
    return out
