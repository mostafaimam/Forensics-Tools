"""Chunked string extraction from a file or device."""

from __future__ import annotations

import re
from dataclasses import dataclass

from utilities_strings.patterns import classify

_CHUNK = 8 << 20


@dataclass
class Hit:
    offset: int
    encoding: str          # ascii | utf-16le | utf-16be
    length: int
    text: str
    category: str = ""
    match: str = ""

    def row(self, hex_offset: bool) -> dict:
        return {
            "offset": f"{self.offset:#x}" if hex_offset else self.offset,
            "encoding": self.encoding, "length": self.length,
            "text": self.text, "category": self.category,
            "match": self.match,
        }


def _res(min_len: int):
    return {
        "ascii": re.compile(rb"[\x09\x20-\x7e]{%d,}" % min_len),
        "utf-16le": re.compile(rb"(?:[\x09\x20-\x7e]\x00){%d,}" % min_len),
        "utf-16be": re.compile(rb"(?:\x00[\x09\x20-\x7e]){%d,}" % min_len),
    }


def _decode(enc: str, raw: bytes) -> str:
    if enc == "ascii":
        return raw.decode("ascii", "replace")
    if enc == "utf-16le":
        return raw.decode("utf-16-le", "replace")
    return raw.decode("utf-16-be", "replace")


def iter_strings(path, *, min_len=4, encodings=("ascii", "utf-16le"),
                 start=0, end=None, max_run=1 << 20, progress=None):
    regexes = {e: r for e, r in _res(min_len).items() if e in encodings}
    overlap = max_run
    from pathlib import Path
    p = Path(path)
    size = None
    try:
        size = p.stat().st_size
    except OSError:
        pass
    with p.open("rb") as fh:
        if start:
            fh.seek(start)
        pos = start
        carry = b""
        carry_base = start
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            buf = carry + block
            buf_base = carry_base
            # only emit matches that START before the overlap tail; the tail
            # is re-examined with the next block
            horizon = len(buf) - (overlap if len(block) == _CHUNK else 0)
            for enc, rx in regexes.items():
                for m in rx.finditer(buf):
                    if m.start() >= horizon:
                        continue
                    off = buf_base + m.start()
                    if off < start:
                        continue
                    if end is not None and off >= end:
                        continue
                    raw = m.group(0)
                    yield Hit(off, enc, len(raw), _decode(enc, raw))
            carry = buf[horizon:]
            carry_base = buf_base + horizon
            pos = buf_base + len(buf)
            if progress and size:
                progress(pos - start, (end or size) - start)
            if end is not None and pos >= end:
                break


def scan(path, *, min_len=4, encodings=("ascii", "utf-16le"), start=0,
         end=None, grep=None, categories=None, classified_only=False,
         limit=None, progress=None):
    rx = re.compile(grep, re.I) if grep else None
    want_class = bool(categories) or classified_only
    n = 0
    for hit in iter_strings(path, min_len=min_len, encodings=encodings,
                            start=start, end=end, progress=progress):
        if rx and not rx.search(hit.text):
            continue
        cats = classify(hit.text, categories) if want_class or not grep else []
        if want_class:
            if not cats:
                continue
            for cat, matched in cats:
                yield Hit(hit.offset, hit.encoding, hit.length, hit.text,
                          cat, matched)
                n += 1
                if limit and n >= limit:
                    return
        else:
            if cats:
                hit.category, hit.match = cats[0]
            yield hit
            n += 1
            if limit and n >= limit:
                return
