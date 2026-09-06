from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Callable, Iterator

from trace_recover.signatures import Signature
from trace_recover.validators import VALIDATORS

_WINDOW = 16 * 1024 * 1024


@dataclass
class Source:
    path: str
    _fh: object = None
    size: int = 0

    def __enter__(self) -> "Source":
        self._fh = open(self.path, "rb", buffering=0)
        self._fh.seek(0, os.SEEK_END)
        self.size = self._fh.tell()
        self._fh.seek(0)
        return self

    def __exit__(self, *exc) -> None:
        if self._fh:
            self._fh.close()

    def read_at(self, offset: int, length: int) -> bytes:
        if offset >= self.size:
            return b""
        self._fh.seek(offset)
        return self._fh.read(min(length, self.size - offset))


@dataclass
class Carving:
    offset: int
    length: int
    signature_id: str
    ext: str
    category: str
    confidence: str          # "structure" | "footer" | "header-only"
    truncated: bool
    md5: str = ""
    sha1: str = ""
    output_path: str = ""

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class ScanOptions:
    min_size: int = 8
    hashes: tuple[str, ...] = ("sha1",)
    nested: bool = False
    max_hits_per_sig: int | None = None


def _compile(sigs: list[Signature]):
    """One capturing group per header, in declared order; ``m.lastindex``
    tells us which header matched."""
    flat = [(h, s) for s in sigs for h in s.headers]
    rx = re.compile(b"|".join(b"(" + re.escape(h) + b")" for h, _ in flat),
                    re.DOTALL)
    return rx, flat


def scan(src: Source, sigs: list[Signature], opts: ScanOptions,
         progress: Callable[[int, int], None] | None = None) -> Iterator[Carving]:
    rx, flat = _compile(sigs)
    max_header = max((len(h) for h, _ in flat), default=1)
    carved: list[tuple[int, int]] = []          # sorted, for nesting checks
    per_sig: dict[str, int] = {}

    pos = 0
    while pos < src.size:
        window = src.read_at(pos, _WINDOW + max_header)
        if not window:
            break
        limit = len(window) if pos + len(window) >= src.size else _WINDOW
        for m in rx.finditer(window):
            if m.start() >= limit:
                break
            gi = m.lastindex
            _hdr, sig = flat[gi - 1]
            hit = pos + m.start()
            start = sig.carve_start(hit)
            if start < 0:
                continue
            if not opts.nested and _inside(carved, start):
                continue
            if opts.max_hits_per_sig and \
                    per_sig.get(sig.id, 0) >= opts.max_hits_per_sig:
                continue

            carving = _carve_one(src, sig, start, opts)
            if carving is None:
                continue
            per_sig[sig.id] = per_sig.get(sig.id, 0) + 1
            _insert(carved, (carving.offset, carving.end))
            yield carving

        if progress:
            progress(min(pos + limit, src.size), src.size)
        pos += limit

    if progress:
        progress(src.size, src.size)


def _carve_one(src: Source, sig: Signature, start: int,
               opts: ScanOptions) -> Carving | None:
    want = min(sig.max_size, src.size - start)
    blob = src.read_at(start, want)
    if len(blob) < opts.min_size:
        return None
    mv = memoryview(blob)

    length = None
    confidence = "header-only"
    if sig.validator and sig.validator in VALIDATORS:
        length = VALIDATORS[sig.validator](mv)
        if length:
            confidence = "structure"
    if length is None and sig.footers:
        skip = max(len(sig.headers[0]), sig.header_at) or 1
        body = bytes(mv[skip:])
        best = None
        for f in sig.footers:
            fp = body.find(f)          # first footer, not last - avoids merging
            if fp >= 0 and (best is None or fp < best[0]):
                best = (fp, f)
        if best is not None:
            fp, foot = best
            length = skip + fp + (len(foot) if sig.footer_inclusive else 0)
            confidence = "footer"
    truncated = False
    if length is None:
        length = len(blob)
        truncated = (start + length) < src.size and length >= sig.max_size
    if length < opts.min_size:
        return None
    length = min(length, len(blob))

    data = blob[:length]
    hashes = _hash(data, opts.hashes)
    return Carving(
        offset=start, length=length, signature_id=sig.id, ext=sig.ext,
        category=sig.category, confidence=confidence, truncated=truncated,
        md5=hashes.get("md5", ""), sha1=hashes.get("sha1", ""),
    )


def _hash(data: bytes, algs) -> dict:
    out = {}
    for a in algs:
        out[a] = hashlib.new(a, data).hexdigest()
    return out


def _inside(ranges: list[tuple[int, int]], offset: int) -> bool:
    for a, b in ranges:
        if a <= offset < b:
            return True
        if a > offset:
            break
    return False


def _insert(ranges: list[tuple[int, int]], item: tuple[int, int]) -> None:
    ranges.append(item)
    ranges.sort()
    if len(ranges) > 4096:                       # keep the nesting check cheap
        del ranges[:2048]
