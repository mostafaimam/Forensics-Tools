"""Locate log files, handle rotation / gzip, and stream records."""

from __future__ import annotations

import gzip
import re
from datetime import datetime, timezone
from pathlib import Path

from linux_syslog.parser import LogRecord, parse_line

# base names we treat as syslog-family text logs (plus their rotations)
_KNOWN = [
    "syslog", "messages", "auth.log", "secure", "kern.log", "cron", "cron.log",
    "daemon.log", "user.log", "mail.log", "auth", "authpriv", "debug",
]
_ROT_RE = re.compile(r"\.(\d+)(\.gz)?$")


def rotation_index(path: Path) -> int:
    """0 for the live file, N for ``name.N`` / ``name.N.gz`` (older = larger)."""
    m = _ROT_RE.search(path.name)
    return int(m.group(1)) if m else 0


def looks_like_log(path: Path) -> bool:
    n = path.name
    stem = _ROT_RE.sub("", n)
    return stem in _KNOWN or stem.endswith(".log")


def discover(root: Path) -> list[Path]:
    out: list[Path] = []
    logdir = root / "var" / "log"
    if not logdir.is_dir():
        # maybe the user pointed straight at a log directory
        logdir = root if root.is_dir() else root.parent
    for p in sorted(logdir.rglob("*")):
        if p.is_file() and looks_like_log(p):
            out.append(p)
    # newest rotation first within a family is irrelevant; sort by family then
    # oldest->newest so continuation lines attach correctly
    out.sort(key=lambda p: (_ROT_RE.sub("", p.name), -rotation_index(p)))
    return out


def open_text(path: Path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            yield from fh
    else:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            yield from fh


def ref_date(path: Path) -> datetime:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    except OSError:
        return datetime.now(timezone.utc)


def iter_records(path: Path, assume_tz: timezone, *, year: int | None = None):
    """Yield :class:`LogRecord` for *path*, folding continuation lines in."""
    rd = ref_date(path)
    if year:
        rd = rd.replace(year=year)
    prev: LogRecord | None = None
    for i, line in enumerate(open_text(path), 1):
        if not line.strip():
            continue
        rec = parse_line(line, ref_date=rd, assume_tz=assume_tz,
                         source_file=str(path), line_no=i)
        if rec.format == "continuation":
            if prev is not None:
                prev.message += "\n" + rec.raw
                prev.raw += "\n" + rec.raw
            else:
                rec.format = "unparsed"
                yield rec
            continue
        if prev is not None:
            yield prev
        prev = rec
    if prev is not None:
        yield prev


def parse_tz(spec: str | None) -> timezone:
    if not spec or spec.upper() in ("UTC", "Z", "+00:00", "+0000"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", spec)
    if not m:
        raise ValueError(f"bad --tz {spec!r} (want e.g. +02:00 or -0500)")
    from datetime import timedelta
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)),
                                     minutes=int(m.group(3))))
