"""Drive the acquisition: read a source, write an image, hash everything."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from acquisition_image import __version__
from acquisition_image.ewf_write import EWFWriter
from acquisition_image.source import Source

_ALGOS = ("md5", "sha1", "sha256")
_READ_CHUNK = 1 << 20


@dataclass
class AcquisitionResult:
    source: str
    output: str
    fmt: str
    bytes_total: int = 0
    bytes_read: int = 0
    padded: int = 0
    sector_size: int = 512
    hashes: dict = field(default_factory=dict)
    verify_hashes: dict = field(default_factory=dict)
    bad_ranges: list = field(default_factory=list)
    segments: list = field(default_factory=list)
    started: str = ""
    finished: str = ""
    seconds: float = 0.0
    verified: str = "not run"          # ok | MISMATCH | not run

    @property
    def ok(self) -> bool:
        return self.verified in ("ok", "not run") and not self.bad_ranges


class _RawSink:
    def __init__(self, out: Path, split: int | None):
        self.base = out
        self.split = split
        self._n = 0
        self._fh = None
        self._in_seg = 0
        self.segments: list[str] = []
        self._open()

    def _open(self):
        self._n += 1
        p = self.base if self.split is None else Path(
            f"{self.base}.{self._n:03d}")
        self._fh = p.open("wb")
        self._in_seg = 0
        self.segments.append(str(p))

    def write(self, data: bytes):
        if self.split is None:
            self._fh.write(data)
            return
        mv = memoryview(data)
        while mv:
            room = self.split - self._in_seg
            take = min(room, len(mv))
            self._fh.write(mv[:take])
            self._in_seg += take
            mv = mv[take:]
            if self._in_seg >= self.split and mv:
                self._fh.close()
                self._open()

    def finalize(self, *_):
        self._fh.close()


def acquire(source_path: str, output: str, fmt: str = "raw", *,
            split_size: int | None = None, segment_size: int | None = None,
            compression: str = "fast", sector_size: int = 512,
            offset: int = 0, length: int | None = None,
            metadata: dict | None = None, progress=None) -> AcquisitionResult:
    src = Source(source_path, sector_size)
    total = src.size if length is None else min(length, src.size - offset)
    out = Path(output)
    is_ewf = fmt in ("ewf", "e01")
    # EWF works in whole sectors; a non-aligned source is zero-padded
    stored_total = ((total + sector_size - 1) // sector_size * sector_size
                    if is_ewf else total)
    pad = stored_total - total
    res = AcquisitionResult(source=source_path, output=output, fmt=fmt,
                            bytes_total=total, sector_size=sector_size,
                            started=_now())
    meta = dict(metadata or {})
    meta.setdefault("version", __version__)
    meta.setdefault("acquired", time.time())

    if is_ewf:
        sink = EWFWriter(output, stored_total, sectors_per_chunk=64,
                         bytes_per_sector=sector_size, compression=compression,
                         segment_size=segment_size, metadata=meta)
    else:
        sink = _RawSink(out, split_size)

    digests = {a: hashlib.new(a) for a in _ALGOS}
    t0 = time.monotonic()
    pos = offset
    end = offset + total
    try:
        while pos < end:
            n = min(_READ_CHUNK, end - pos)
            data = src.read(pos, n)
            for d in digests.values():
                d.update(data)
            sink.write(data)
            pos += n
            res.bytes_read += n
            if progress:
                progress(res.bytes_read, total, time.monotonic() - t0)
        if pad:
            filler = b"\x00" * pad
            for d in digests.values():
                d.update(filler)
            sink.write(filler)
            res.padded = pad
        res.hashes = {a: d.hexdigest() for a, d in digests.items()}
        sink.finalize(res.hashes["md5"], res.hashes["sha1"])
    finally:
        src.close()

    res.seconds = round(time.monotonic() - t0, 2)
    res.finished = _now()
    res.bad_ranges = [{"offset": o, "length": ln} for o, ln in src.bad_ranges]
    res.segments = getattr(sink, "segments", [output])
    return res


def verify(image_path: str, fmt: str | None = None,
           expected: dict | None = None, progress=None) -> dict:
    """Re-read an image and hash it.  Returns {algo: hex, ...} plus 'match'."""
    p = Path(image_path)
    fmt = fmt or _sniff(p)
    digests = {a: hashlib.new(a) for a in _ALGOS}
    stored = {}
    total_done = 0

    if fmt in ("ewf", "e01"):
        from acquisition_image.ewf_read import EWFReader
        r = EWFReader(image_path)
        stored = {"md5": r.stored_md5, "sha1": r.stored_sha1}
        size = r.size
        for chunk in r.chunks():
            for d in digests.values():
                d.update(chunk)
            total_done += len(chunk)
            if progress:
                progress(total_done, size, 0)
        r.close()
    else:
        parts = _raw_parts(p)
        size = sum(x.stat().st_size for x in parts)
        for part in parts:
            with part.open("rb") as fh:
                while True:
                    b = fh.read(_READ_CHUNK)
                    if not b:
                        break
                    for d in digests.values():
                        d.update(b)
                    total_done += len(b)
                    if progress:
                        progress(total_done, size, 0)

    out = {a: d.hexdigest() for a, d in digests.items()}
    ref = expected or {k: v for k, v in stored.items() if v}
    out["stored"] = {k: v for k, v in stored.items() if v}
    out["match"] = bool(ref) and all(
        out.get(k) == v for k, v in ref.items() if v)
    out["compared_against"] = "expected" if expected else (
        "embedded digest" if ref else "nothing (no reference)")
    return out


def _raw_parts(p: Path) -> list[Path]:
    if p.exists() and p.is_file() and not p.suffix[1:].isdigit():
        return [p]
    stem = p if not p.suffix[1:].isdigit() else p.with_suffix("")
    parts = sorted(x for x in p.parent.glob(stem.name + ".*")
                   if x.suffix[1:].isdigit())
    return parts or [p]


def _sniff(p: Path) -> str:
    try:
        with p.open("rb") as fh:
            if fh.read(8) in (b"EVF\x09\x0d\x0a\xff\x00",
                              b"LVF\x09\x0d\x0a\xff\x00"):
                return "ewf"
    except OSError:
        pass
    if p.suffix.lower() in (".e01", ".ex01", ".s01"):
        return "ewf"
    return "raw"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
