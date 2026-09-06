"""Pool-tag scan for _EPROCESS candidates (Windows, profile-independent)."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MIN_FT = int((datetime(2012, 1, 1, tzinfo=timezone.utc) - _FT_EPOCH)
              .total_seconds() * 10_000_000)
_MAX_FT = int((datetime(2038, 1, 1, tzinfo=timezone.utc) - _FT_EPOCH)
              .total_seconds() * 10_000_000)

_TAGS = {b"Proc": "Proc", b"Pro\xe3": "Proc(protected)"}
_TAG_RE = re.compile(rb"Proc|Pro\xe3")
_WINDOW = 0xE00
_NAME_RE = re.compile(rb"(?<![\x21-\x7e])([\x21-\x7e ]{2,15})\x00")
_KNOWN = (b"System", b"Registry", b"smss.exe", b"csrss.exe", b"wininit.exe",
          b"services.exe", b"lsass.exe", b"svchost.exe", b"explorer.exe",
          b"winlogon.exe", b"System")


@dataclass
class Process:
    pid: int
    ppid: int
    name: str
    create_time: str
    exit_time: str
    phys_offset: int
    pool_tag: str
    confidence: str          # high | medium | low
    exited: bool

    def key(self):
        return (self.pid, self.name.lower(), self.create_time[:19])


def ft_to_iso(ticks: int) -> str:
    if not (_MIN_FT <= ticks <= _MAX_FT):
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return ""


def _first_times(buf: bytes):
    """The first plausible CreateTime FILETIME and the ExitTime 8 bytes after."""
    for i in range(0, len(buf) - 16, 8):
        c = struct.unpack_from("<Q", buf, i)[0]
        if not (_MIN_FT <= c <= _MAX_FT):
            continue
        e = struct.unpack_from("<Q", buf, i + 8)[0]
        if e == 0 or (_MIN_FT <= e <= _MAX_FT and e >= c):
            return i, c, e
    return None


def _pid_candidates(buf: bytes):
    seen = set()
    for i in range(0, len(buf) - 8, 4):
        v = struct.unpack_from("<Q", buf, i)[0]
        if 0 < v < 0x40000 and v % 4 == 0:
            if i not in seen:
                seen.add(i)
                yield i, v


def scan(img, *, progress=None):
    results: list[Process] = []
    scanned = 0
    for base, block in img.stream_runs():
        for m in _TAG_RE.finditer(block):
            t = m.start()
            tag = _TAGS.get(block[t:t + 4], "Proc")
            # the pool allocation starts at the tag - 4 and is 8-aligned
            start = max(0, (t - 4) & ~7)
            win = block[start: t + _WINDOW]
            proc = _parse_candidate(win, base + start, tag)
            if proc:
                results.append(proc)
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)
    # dedupe
    best: dict = {}
    for p in results:
        k = p.key()
        if k not in best or _rank(p) > _rank(best[k]):
            best[k] = p
    return sorted(best.values(), key=lambda p: (p.pid, p.name.lower()))


def _rank(p: Process) -> int:
    return {"high": 3, "medium": 2, "low": 1}[p.confidence]


def _parse_candidate(win: bytes, phys_base: int, tag: str):
    names = list(_NAME_RE.finditer(win))
    if not names:
        return None
    # prefer a name that looks like an executable / known process
    def name_score(nm: bytes) -> int:
        s = 0
        if nm in _KNOWN:
            s += 3
        if nm.lower().endswith(b".exe"):
            s += 2
        if 3 <= len(nm) <= 15:
            s += 1
        return s
    names.sort(key=lambda mm: -name_score(mm.group(1)))
    nm = names[0]
    name = nm.group(1).decode("latin-1", "replace")
    name_off = nm.start()

    create_iso = exit_iso = ""
    exited = False
    ft = _first_times(win)
    if ft:
        _off, c, e = ft
        create_iso = ft_to_iso(c)
        if e:
            exit_iso = ft_to_iso(e)
            exited = True

    pid = ppid = 0
    pids = sorted(_pid_candidates(win), key=lambda p: abs(p[0] - name_off))
    if pids:
        pid = pids[0][1]
        if len(pids) > 1:
            ppid = pids[1][1]

    conf = "low"
    if name.lower().endswith(".exe") or nm.group(1) in _KNOWN:
        conf = "medium"
    if create_iso and pid:
        conf = "high" if conf == "medium" else "medium"
    if not create_iso and not pid and conf == "low":
        return None

    return Process(pid=pid, ppid=ppid, name=name, create_time=create_iso,
                   exit_time=exit_iso, phys_offset=phys_base, pool_tag=tag,
                   confidence=conf, exited=exited)
