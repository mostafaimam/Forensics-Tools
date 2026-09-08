from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_cmdline import __version__, tracelib
from memory_cmdline.cmdline import scan
from memory_cmdline.loader import MemoryImage, MemoryImageError
from memory_cmdline.output import COLUMNS, render, row

_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_cmdline",
        description="Recover every process's command line, image path, working "
                    "directory and window title from a Windows RAM dump by "
                    "walking _EPROCESS -> PEB -> RTL_USER_PROCESS_PARAMETERS. "
                    "Flags living-off-the-land patterns and argv[0] "
                    "masquerading. Profile-independent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_cmdline MEMORY.DMP\n"
            "  memory_cmdline mem.lime --notable-only --csv suspicious.csv\n"
            "  memory_cmdline mem.raw --process powershell --env\n"
            "  memory_cmdline MEMORY.DMP --grep 'http|-enc' --json hits.json\n"
        ),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_cmdline {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--process", metavar="SUBSTR",
                   help="keep processes whose name matches this substring")
    p.add_argument("--pid", type=int, action="append", default=[])
    p.add_argument("--grep", metavar="REGEX",
                   help="keep rows whose command line matches (case-insensitive)")
    p.add_argument("--notable-only", action="store_true",
                   help="only rows with at least one heuristic flag")
    p.add_argument("--min-severity", choices=["low", "medium", "high"],
                   default=None)
    p.add_argument("--unresolved", action="store_true",
                   help="also show processes with no command line recovered")
    p.add_argument("--env", action="store_true",
                   help="also parse the environment block (JSON output)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_cmdline.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_cmdline", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))
    try:
        img = MemoryImage(a.image)
    except MemoryImageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    import re
    grep = re.compile(a.grep, re.I) if a.grep else None

    prog = None
    if not a.quiet:
        def prog(done, total):  # noqa: E306
            sys.stderr.write(f"\r  {done}/{total} processes")
            sys.stderr.flush()

    rows = scan(img, want_env=a.env, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    kept = []
    for r in rows:
        if not a.unresolved and not a.notable_only and not r.resolved \
                and not r.image_path:
            continue
        if a.process and a.process.lower() not in r.process.lower():
            continue
        if a.pid and r.pid not in a.pid:
            continue
        if grep and not grep.search(r.command_line):
            continue
        if a.notable_only and not r.notable:
            continue
        if a.min_severity and _ORDER[r.severity] < _ORDER[a.min_severity]:
            continue
        kept.append(r)

    if a.csv:
        tracelib.write_csv([row(r) for r in kept], a.csv, COLUMNS,
                           ctx, confidence="heuristic", tz="utc-native")
    if a.json:
        tracelib.write_json([row(r) for r in kept], a.json, ctx,
                            confidence="heuristic", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(kept), end="")

    flagged = sum(1 for r in kept if r.notable)
    hi = sum(1 for r in kept if r.severity == "high")
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_cmdline: {len(kept)} process(es), {flagged} flagged "
          f"({hi} high)", file=sys.stderr)
    return 0 if kept else 1


if __name__ == "__main__":
    raise SystemExit(main())
