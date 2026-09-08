from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_svcscan import __version__, tracelib
from memory_svcscan.analyze import scan
from memory_svcscan.loader import MemoryImage, MemoryImageError
from memory_svcscan.output import COLUMNS, render, row

_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_svcscan",
        description="Recover the Windows service database from services.exe "
                    "memory by scanning for _SERVICE_RECORD (sErv) structures "
                    "- finds services missing from the registry. "
                    "Profile-independent; fields are content-derived so "
                    "expect some partial rows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_svcscan MEMORY.DMP\n"
            "  memory_svcscan mem.lime --running --csv services.csv\n"
            "  memory_svcscan mem.raw --notable-only --json suspicious.json\n"
            "  memory_svcscan MEMORY.DMP --type kernel-driver\n"
        ),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_svcscan {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--running", action="store_true",
                   help="keep only RUNNING services")
    p.add_argument("--type", metavar="SUBSTR",
                   help="keep services whose type matches (e.g. driver, win32)")
    p.add_argument("--name", metavar="SUBSTR",
                   help="keep services whose name / display name matches")
    p.add_argument("--notable-only", action="store_true",
                   help="only services with at least one heuristic flag")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--min-confidence", choices=["low", "medium", "high"],
                   default="low")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_svcscan.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_svcscan", __version__)
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

    rows = scan(img, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    conf = {"low": 0, "medium": 1, "high": 2}
    kept = []
    for r in rows:
        if a.running and r.state != "RUNNING":
            continue
        if a.type and a.type.lower() not in r.type.lower():
            continue
        if a.name and a.name.lower() not in (r.name + " "
                                             + r.display_name).lower():
            continue
        if a.notable_only and not r.notable:
            continue
        if a.min_severity and _ORDER[r.severity] < _ORDER[a.min_severity]:
            continue
        if conf[r.confidence] < conf[a.min_confidence]:
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
    running = sum(1 for r in kept if r.state == "RUNNING")
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_svcscan: {len(kept)} service(s), {running} running, "
          f"{flagged} flagged", file=sys.stderr)
    return 0 if kept else 1


if __name__ == "__main__":
    raise SystemExit(main())
