"""Per-format history-file parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ParsedEntry:
    command: str
    timestamp: datetime | None = None
    start_line: int = 0
    note: str = ""          # e.g. "out-of-order", "history cleared"


def _epoch(v: str) -> datetime | None:
    try:
        n = int(v)
    except ValueError:
        return None
    if n < 100_000_000 or n > 4_102_444_800:      # ~1973 .. 2100
        return None
    return datetime.fromtimestamp(n, timezone.utc)


_BASH_TS_RE = re.compile(r"^#(\d{9,13})\s*$")


def parse_bash(text: str):
    lines = text.splitlines()
    has_ts = any(_BASH_TS_RE.match(ln) for ln in lines)
    pending_ts: datetime | None = None
    buf: list[str] = []
    start = 0
    for i, ln in enumerate(lines, 1):
        m = _BASH_TS_RE.match(ln)
        if m:
            if buf:
                yield ParsedEntry("\n".join(buf), pending_ts, start)
                buf = []
            pending_ts = _epoch(m.group(1))
            start = i
            continue
        if not has_ts:
            if ln.strip() == "":
                continue
            yield ParsedEntry(ln, None, i)
            continue
        if not buf:
            start = start or i
        buf.append(ln)
    if buf:
        yield ParsedEntry("\n".join(buf), pending_ts, start)


_ZSH_RE = re.compile(r"^:\s*(\d+):(\d+);(.*)$", re.DOTALL)


def parse_zsh(text: str):
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        ln = lines[i]
        m = _ZSH_RE.match(ln)
        if m:
            ts = _epoch(m.group(1))
            cmd = m.group(3)
            start = i + 1
            while cmd.endswith("\\") and i + 1 < n:
                i += 1
                cmd = cmd[:-1] + "\n" + lines[i]
            yield ParsedEntry(cmd, ts, start)
        elif ln.strip():
            yield ParsedEntry(ln, None, i + 1)
        i += 1


def parse_fish(text: str):
    lines = text.splitlines()
    cmd = None
    ts = None
    start = 0
    for i, ln in enumerate(lines, 1):
        if ln.startswith("- cmd: "):
            if cmd is not None:
                yield ParsedEntry(_fish_unescape(cmd), ts, start)
            cmd = ln[len("- cmd: "):]
            ts = None
            start = i
        elif ln.lstrip().startswith("when:") and cmd is not None:
            ts = _epoch(ln.split("when:", 1)[1].strip())
        elif ln.startswith("  ") and cmd is not None and not ln.lstrip().startswith(
                ("paths:", "-", "when:")):
            cmd += "\n" + ln.strip()
    if cmd is not None:
        yield ParsedEntry(_fish_unescape(cmd), ts, start)


def _fish_unescape(s: str) -> str:
    return s.replace("\\n", "\n").replace("\\\\", "\\")


def parse_plain(text: str):
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.strip():
            yield ParsedEntry(ln, None, i)


def parse_mysql(text: str):
    # mysql escapes newlines as \040? actually spaces stay; multi-line uses
    # a literal backslash-n is not used - keep it simple, one line per entry
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.strip():
            yield ParsedEntry(ln.replace("\\040", " "), None, i)


# filename (lowercased, no leading dot) -> (shell label, parser)
_BY_NAME = {
    "bash_history": ("bash", parse_bash),
    "sh_history": ("sh", parse_bash),
    "ash_history": ("ash", parse_bash),
    "history": ("sh", parse_bash),
    "zsh_history": ("zsh", parse_zsh),
    "zhistory": ("zsh", parse_zsh),
    "fish_history": ("fish", parse_fish),
    "python_history": ("python", parse_plain),
    "node_repl_history": ("node", parse_plain),
    "psql_history": ("psql", parse_plain),
    "sqlite_history": ("sqlite", parse_plain),
    "rediscli_history": ("redis", parse_plain),
    "irb_history": ("irb", parse_plain),
    "mysql_history": ("mysql", parse_mysql),
}


def for_name(name: str):
    key = name.lower().lstrip(".")
    if key in _BY_NAME:
        return _BY_NAME[key]
    if key.endswith("_history") or key.endswith("history"):
        return (key.split("_")[0] or "shell", parse_plain)
    return None
