"""Low-level access to the WMI repository files.

Full parsing of the CIM repository (page mapping, index B-tree, class
layouts) is large; for persistence hunting the reliable, tool-independent
approach is to work over the string content of ``OBJECTS.DATA``.  This
module extracts ASCII and UTF-16LE strings with their byte offsets and,
when ``MAPPING*.MAP`` is present, records which physical pages are live so
callers can down-weight stale records.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

PAGE = 0x2000
_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


@dataclass
class Str:
    text: str
    offset: int
    wide: bool


_MARKER_CLASSES = (
    "__EventFilter", "__FilterToConsumerBinding", "__EventConsumer",
    "CommandLineEventConsumer", "ActiveScriptEventConsumer",
    "LogFileEventConsumer", "NTEventLogEventConsumer", "SMTPEventConsumer",
    "ScriptingStandardConsumerSetting", "__AbsoluteTimerInstruction",
    "__IntervalTimerInstruction", "__NamespaceCreationEvent",
    "__ClassCreationEvent", "__MethodInvocationEvent",
)


@dataclass
class Repo:
    objects: bytes
    strings: list          # list[Str] sorted by offset
    live_pages: set         # physical page numbers referenced by MAPPING
    source: str
    markers: list = None    # sorted list[int] of class-marker offsets

    def _marker_offsets(self):
        if self.markers is None:
            offs = []
            for cls in _MARKER_CLASSES:
                start = 0
                pat = cls.encode() + b"\x00"
                while True:
                    i = self.objects.find(pat, start)
                    if i < 0:
                        break
                    offs.append(i)
                    start = i + 1
            self.markers = sorted(offs)
        return self.markers

    def near(self, offset: int, before: int = 220, after: int = 3200):
        lo, hi = offset - before, offset + after
        # clip forward to just before the next class marker
        for mo in self._marker_offsets():
            if offset < mo <= hi:
                hi = mo - 1
                break
        for mo in reversed(self._marker_offsets()):
            if lo <= mo < offset:
                lo = mo + len(b"marker")
                break
        return [s for s in self.strings if lo <= s.offset <= hi]

    def page_live(self, offset: int) -> bool:
        if not self.live_pages:
            return True
        return (offset // PAGE) in self.live_pages


def _extract_strings(data: bytes) -> list[Str]:
    out: list[Str] = []
    for m in _UTF16.finditer(data):
        raw = m.group()
        try:
            out.append(Str(raw.decode("utf-16-le"), m.start(), True))
        except UnicodeDecodeError:
            pass
    covered = []
    for m in _ASCII.finditer(data):
        s = m.group().decode("latin-1")
        # skip the ascii half of a wide string
        out.append(Str(s, m.start(), False))
        covered.append(s)
    out.sort(key=lambda s: s.offset)
    return out


def _parse_mapping(path: Path) -> set[int]:
    """Return the set of physical OBJECTS.DATA pages the mapping points at."""
    try:
        data = path.read_bytes()
    except OSError:
        return set()
    pages: set[int] = set()
    # MAPPING format: header, u32 count, then count x mapping entries.
    # Entry layout varies by OS; the physical page number is the first u32
    # of each entry and 0xffffffff marks an unused slot.  Scan for a
    # plausible count and read u32s.
    for base in (0x18, 0x1C, 0x20, 0x28):
        if base + 4 > len(data):
            continue
        count = struct.unpack_from("<I", data, base)[0]
        if 0 < count < 500000 and base + 4 + count * 4 <= len(data):
            for i in range(count):
                v = struct.unpack_from("<I", data, base + 4 + i * 4)[0]
                if v != 0xFFFFFFFF and v < 500000:
                    pages.add(v)
            if pages:
                return pages
    return pages


def load(path: str) -> list[Repo]:
    p = Path(path)
    out: list[Repo] = []
    objs: list[Path] = []
    if p.is_file():
        objs = [p]
    elif p.is_dir():
        for f in p.rglob("*"):
            if f.is_file() and f.name.lower() == "objects.data":
                objs.append(f)
    for od in objs:
        try:
            data = od.read_bytes()
        except OSError:
            continue
        live: set[int] = set()
        parent = od.parent
        maps = sorted(parent.glob("MAPPING*.MAP")) + \
            sorted(parent.glob("Mapping*.map"))
        best: set[int] = set()
        for mp in maps:
            got = _parse_mapping(mp)
            if len(got) > len(best):
                best = got
        live = best
        out.append(Repo(objects=data, strings=_extract_strings(data),
                        live_pages=live, source=str(od)))
    return out
