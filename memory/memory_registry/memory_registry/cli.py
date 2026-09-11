from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_registry import __version__, tracelib
from memory_registry.hivescan import scan
from memory_registry.loader import MemoryImage, MemoryImageError

COLUMNS = ["file_name", "dirty", "seq1", "seq2", "last_written", "version",
          "length", "phys_offset"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_registry",
        description="List the registry hives mapped in a Windows RAM dump "
                    "by scanning for the 'regf' base-block signature every "
                    "loaded hive keeps memory-resident, and decoding it "
                    "directly: file path, sequence numbers (mismatched = "
                    "dirty / unflushed), last-written FILETIME, format "
                    "version. Recovers hives whose backing file was later "
                    "deleted. Profile-independent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  memory_registry MEMORY.DMP\n"
                "  memory_registry mem.lime --dirty-only --csv hives.csv\n"
                "  memory_registry mem.raw --name NTUSER --json hives.json\n"),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_registry {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--dirty-only", action="store_true")
    p.add_argument("--name", metavar="SUBSTR",
                   help="match the hive file path")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_registry.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_registry", __version__)
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

    hives = scan(img, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    rows = []
    for h in hives:
        if a.dirty_only and not h.dirty:
            continue
        if a.name and a.name.lower() not in h.file_name.lower():
            continue
        rows.append(h.row())

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = "  [DIRTY]" if r["dirty"] == "yes" else ""
            print(f"{r['file_name']:<60} v{r['version']}  "
                  f"{r['last_written']}{mark}")

    ctx.finish(outputs=[a.csv, a.json])
    dirty = sum(1 for r in rows if r["dirty"] == "yes")
    print(f"memory_registry: {len(rows)} hive(s), {dirty} dirty",
          file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
