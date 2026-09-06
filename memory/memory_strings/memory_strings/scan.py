"""Extract string runs from a memory image and (optionally) classify them."""

from __future__ import annotations

import re
from dataclasses import dataclass

from memory_strings.patterns import classify


@dataclass
class Hit:
    phys: int
    encoding: str        # ascii | utf-16le
    length: int
    text: str
    category: str = ""
    match: str = ""


def _compile(min_len: int):
    return (re.compile(rb"[\x09\x20-\x7e]{%d,}" % min_len),
            re.compile(rb"(?:[\x09\x20-\x7e]\x00){%d,}" % min_len))


def _inrange(a, lo, hi):
    return (lo is None or a >= lo) and (hi is None or a < hi)


def iter_strings(img, *, min_len=4, want_ascii=True, want_unicode=True,
                 phys_from=None, phys_to=None):
    ascii_re, u16_re = _compile(min_len)
    for base, block in img.stream_runs():
        if phys_to is not None and base >= phys_to:
            break
        if phys_from is not None and base + len(block) <= phys_from:
            continue
        if want_ascii:
            for m in ascii_re.finditer(block):
                a = base + m.start()
                if _inrange(a, phys_from, phys_to):
                    yield Hit(a, "ascii", m.end() - m.start(),
                              m.group(0).decode("ascii"))
        if want_unicode:
            for m in u16_re.finditer(block):
                a = base + m.start()
                if _inrange(a, phys_from, phys_to):
                    yield Hit(a, "utf-16le", len(m.group(0)),
                              m.group(0).decode("utf-16-le", "replace"))


def scan(img, *, min_len=4, want_ascii=True, want_unicode=True, grep=None,
         categories=None, classified_only=False, phys_from=None, phys_to=None,
         limit=None):
    rx = re.compile(grep, re.IGNORECASE) if grep else None
    want_class = bool(categories) or classified_only
    n = 0
    for hit in iter_strings(img, min_len=min_len, want_ascii=want_ascii,
                            want_unicode=want_unicode, phys_from=phys_from,
                            phys_to=phys_to):
        if rx and not rx.search(hit.text):
            continue
        cats = classify(hit.text, categories) if (want_class or not grep) else []
        if want_class:
            if not cats:
                continue
            for cat, matched in cats:
                yield Hit(hit.phys, hit.encoding, hit.length, hit.text, cat,
                          matched)
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
