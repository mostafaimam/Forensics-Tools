from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_dlllist import __version__
from memory_dlllist.dlllist import scan
from memory_dlllist.loader import MemoryImage, MemoryImageError
from memory_dlllist.output import COLUMNS, render, row, write_csv, write_json

_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_dlllist",
        description="Enumerate loaded modules per process from a Windows RAM "
                    "dump by image-VAD pool-tag scanning; recovers each "
                    "module's full path and flags modules loaded from "
                    "user-writable directories, mislocated system DLLs, and "
                    "executable image regions with no backing file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_dlllist MEMORY.DMP\n"
            "  memory_dlllist mem.lime --process powershell --csv mods.csv\n"
            "  memory_dlllist mem.raw --notable-only --json suspicious.json\n"
            "  memory_dlllist MEMORY.DMP --unbacked-only\n"
        ),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_dlllist {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--process", metavar="SUBSTR",
                   help="keep rows whose owning process matches this substring")
    p.add_argument("--pid", type=int, action="append", default=[])
    p.add_argument("--name", metavar="SUBSTR",
                   help="keep modules whose file name matches")
    p.add_argument("--notable-only", action="store_true",
                   help="only modules with at least one heuristic flag")
    p.add_argument("--unbacked-only", action="store_true",
                   help="only executable image regions with no backing file")
    p.add_argument("--min-confidence", choices=["low", "medium", "high"],
                   default="low")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_dlllist.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
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

    mods = scan(img, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    kept = []
    for m in mods:
        if a.process and a.process.lower() not in m.process.lower():
            continue
        if a.pid and m.pid not in a.pid:
            continue
        if a.name and a.name.lower() not in m.name.lower():
            continue
        if a.notable_only and not m.notable:
            continue
        if a.unbacked_only and "unbacked-image" not in m.notable:
            continue
        if _ORDER[m.confidence] < _ORDER[a.min_confidence]:
            continue
        kept.append(m)

    rows = [row(m) for m in kept]
    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(kept), end="")

    flagged = sum(1 for m in kept if m.notable)
    procs = len({m.pid for m in kept if m.pid})
    print(f"memory_dlllist: {len(kept)} module(s) across {procs} process(es), "
          f"{flagged} flagged", file=sys.stderr)
    return 0 if kept else 1


if __name__ == "__main__":
    raise SystemExit(main())
