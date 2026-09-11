from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from memory_handles import __version__, flags, tracelib
from memory_handles.handles import enumerate_file_handles
from memory_handles.loader import MemoryImage, MemoryImageError

COLUMNS = ["pid", "process", "handle", "type", "name", "severity", "notable"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_handles",
        description="Per-process open file handles from a Windows RAM dump: "
                    "locates each process's ObjectTable by validating "
                    "candidate _EPROCESS offsets against the resulting "
                    "_HANDLE_TABLE shape, walks the (1-3 level) table, "
                    "decodes each entry to an object address (trying the "
                    "handful of bit-layouts Windows has used), and reports "
                    "the ones that resolve to a _FILE_OBJECT. v0.1 recovers "
                    "file handles only. Profile-independent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  memory_handles MEMORY.DMP\n"
                "  memory_handles mem.lime --process lsass.exe --csv h.csv\n"
                "  memory_handles mem.raw --notable-only\n"),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_handles {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--process", metavar="SUBSTR")
    p.add_argument("--pid", type=int)
    p.add_argument("--grep", metavar="REGEX", help="match the handle name")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_handles.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_handles", __version__)
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

    prog = None
    if not a.quiet:
        def prog(done, total):  # noqa: E306
            pct = f"{100 * done // total}%" if total else str(done)
            sys.stderr.write(f"\r  scanning {pct}")
            sys.stderr.flush()

    handles = enumerate_file_handles(img, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    _SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for h in handles:
        if a.process and a.process.lower() not in h.process.lower():
            continue
        if a.pid is not None and h.pid != a.pid:
            continue
        if grep and not grep.search(h.name):
            continue
        notable = flags.flag(h.process, h.name)
        row = h.row()
        row["notable"] = ";".join(notable)
        row["severity"] = flags.severity(notable)
        if a.notable_only and not notable:
            continue
        if a.min_severity and _SEV[row["severity"]] < _SEV[a.min_severity]:
            continue
        rows.append(row)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="heuristic", tz="n/a")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            print(f"{r['pid']:>6} {r['process']:<20} {r['handle']:<8} "
                  f"{r['name']}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"       ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_handles: {len(rows)} file handle(s), "
          f"{sum(1 for r in rows if r['notable'])} flagged "
          f"(worst: {flags.worst(rows)})", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
