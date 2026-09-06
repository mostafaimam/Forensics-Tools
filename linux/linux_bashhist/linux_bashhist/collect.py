"""Locate history files for every user under a filesystem root."""

from __future__ import annotations

from pathlib import Path

from linux_bashhist.parsers import for_name
from linux_bashhist.scan import Entry

# extra histories that live at a fixed nested path
_NESTED = [
    ".local/share/fish/fish_history",
]

_HIST_SUFFIXES = ("_history", "history")
_SKIP = {".git", ".cache", "node_modules", ".cargo", ".rustup", ".npm"}


def _homes(root: Path):
    """Yield (username, home_path)."""
    r = root / "root"
    if r.is_dir():
        yield "root", r
    home = root / "home"
    if home.is_dir():
        for d in sorted(home.iterdir()):
            if d.is_dir():
                yield d.name, d
    # some systems: /Users (WSL-mounted mac), /export/home
    for alt in ("Users", "export/home", "var/lib"):
        p = root / alt
        if p.is_dir():
            for d in sorted(p.iterdir()):
                if d.is_dir() and (d / ".bash_history").exists():
                    yield d.name, d


def _history_files(home: Path):
    for f in sorted(home.iterdir()) if home.is_dir() else []:
        if f.is_file() and f.name.startswith(".") \
                and f.name.lower().endswith(_HIST_SUFFIXES):
            yield f
    for rel in _NESTED:
        p = home / rel
        if p.is_file():
            yield p


def entries_from_file(path: Path, user: str):
    match = for_name(path.name)
    if match is None:
        return
    shell, parser = match
    try:
        text = path.read_text("utf-8", errors="replace")
    except OSError:
        return
    prev_ts = None
    out_of_order = False
    parsed = list(parser(text))
    for pe in parsed:
        e = Entry(user=user, shell=shell, timestamp=pe.timestamp,
                  command=pe.command, note=pe.note, source_file=str(path),
                  line_no=pe.start_line)
        if pe.timestamp and prev_ts and pe.timestamp < prev_ts:
            out_of_order = True
            e.note = (e.note + "; " if e.note else "") + "timestamp < previous"
        if pe.timestamp:
            prev_ts = pe.timestamp
        e.flag()
        yield e
    # a shell-history file that exists but is empty is itself worth noting
    if not parsed and path.name.lower().endswith(("bash_history", "zsh_history")):
        e = Entry(user=user, shell=shell, command="", source_file=str(path),
                  note="history file present but empty (possible wipe)")
        yield e
    if out_of_order:
        # emit a summary marker row
        e = Entry(user=user, shell=shell, source_file=str(path),
                  note="file contains out-of-order timestamps (possible tampering)")
        yield e


def collect_root(root: Path):
    for user, home in _homes(root):
        for f in _history_files(home):
            yield from entries_from_file(f, user)


def collect_file(path: Path, user: str | None):
    u = user or _guess_user(path)
    yield from entries_from_file(path, u)


def _guess_user(path: Path) -> str:
    for part in path.parts:
        if part == "root":
            return "root"
    parts = path.parts
    if "home" in parts:
        idx = parts.index("home")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""
