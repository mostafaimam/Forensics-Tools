from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_malfind import __version__, tracelib
from memory_malfind.loader import MemoryImage, MemoryImageError
from memory_malfind.malfind import scan
from memory_malfind.output import COLUMNS, render, row

_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_malfind",
        description="Find injected / unbacked executable memory in a Windows "
                    "RAM dump - private (VadS) regions that are executable: "
                    "reflectively-loaded DLLs, hollowed sections, shellcode. "
                    "Profile-independent pool-tag scan; expect some false "
                    "positives (JIT compilers legitimately allocate RWX).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_malfind MEMORY.DMP\n"
            "  memory_malfind mem.lime --min-confidence medium --csv hits.csv\n"
            "  memory_malfind mem.raw --process powershell --json malfind.json\n"
            "  memory_malfind MEMORY.DMP --rwx-only\n"
        ),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_malfind {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--process", metavar="SUBSTR",
                   help="keep rows whose owning process matches this substring")
    p.add_argument("--pid", type=int, action="append", default=[])
    p.add_argument("--verdict", action="append", default=[], metavar="KIND",
                   choices=["pe", "shellcode", "unbacked-exec", "rwx-data"],
                   help="keep only these verdicts (repeatable)")
    p.add_argument("--rwx-only", action="store_true",
                   help="only PAGE_EXECUTE_READWRITE regions")
    p.add_argument("--min-confidence", choices=["low", "medium", "high"],
                   default="low")
    p.add_argument("--all-exec", action="store_true",
                   help="also list plain EXECUTE / EXECUTE_READ regions "
                        "(not just the suspicious set)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_malfind.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_malfind", __version__)
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
        def prog(stage, done, total):  # noqa: E306
            pct = f"{100 * done // total}%" if total else str(done)
            sys.stderr.write(f"\r  {stage} scan {pct}")
            sys.stderr.flush()

    dets = scan(img, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    kept = []
    for d in dets:
        if a.process and a.process.lower() not in d.process.lower():
            continue
        if a.pid and d.pid not in a.pid:
            continue
        if a.verdict and d.verdict not in a.verdict:
            continue
        if a.rwx_only and d.protection != "EXECUTE_READWRITE":
            continue
        if _ORDER[d.confidence] < _ORDER[a.min_confidence]:
            continue
        if not a.all_exec and d.verdict == "unbacked-exec" \
                and d.confidence == "low" and not d.zeroed:
            continue
        kept.append(d)

    rows = [row(d) for d in kept]
    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="heuristic", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(kept), end="")

    hi = sum(1 for d in kept if d.confidence == "high")
    procs = len({d.pid for d in kept if d.pid})
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_malfind: {len(kept)} region(s) across {procs} process(es), "
          f"{hi} high-confidence", file=sys.stderr)
    return 0 if kept else 1


if __name__ == "__main__":
    raise SystemExit(main())
