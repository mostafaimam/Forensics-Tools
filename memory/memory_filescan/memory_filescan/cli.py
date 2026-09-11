from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from memory_filescan import __version__, flags, tracelib
from memory_filescan.filescan import scan
from memory_filescan.loader import MemoryImage, MemoryImageError

COLUMNS = ["name", "device", "severity", "notable", "phys_offset"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_filescan",
        description="Recover open _FILE_OBJECT names from a Windows RAM "
                    "dump: pool-tag scan for 'File', validated by a "
                    "plausible FileName UNICODE_STRING and resolved through "
                    "the kernel page tables (the name buffer lives in "
                    "kernel space, so no per-process attribution is "
                    "needed). Finds files open at capture time, including "
                    "ones since deleted from disk.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  memory_filescan MEMORY.DMP\n"
                "  memory_filescan mem.lime --notable-only --csv files.csv\n"
                "  memory_filescan mem.raw --grep '\\.docx$'\n"),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_filescan {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--grep", metavar="REGEX")
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
        from memory_filescan.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_filescan", __version__)
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

    hits = scan(img, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    _SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for h in hits:
        if grep and not grep.search(h.name):
            continue
        notable = flags.flag(h.name)
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
            print(f"{r['name']}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_filescan: {len(rows)} file object(s), "
          f"{sum(1 for r in rows if r['notable'])} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
