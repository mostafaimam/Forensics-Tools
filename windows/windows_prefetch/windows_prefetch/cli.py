from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from windows_prefetch import __version__, tracelib
from windows_prefetch.models import PrefetchFile
from windows_prefetch.output import (
    render_table,
    write_files_csv,
    write_json,
    write_jsonl,
    write_summary_csv,
)
from windows_prefetch.parser import parse_file


def _iter_pf_paths(paths, recursive):
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield str(p)
        elif p.is_dir():
            it = p.rglob("*") if recursive else p.iterdir()
            for child in sorted(it):
                if child.is_file() and child.suffix.lower() == ".pf":
                    yield str(child)
        else:
            yield str(p)  # non-existent - parse_file emits an error row


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_prefetch",
        description="Parse Windows Prefetch (.pf) files - versions 17-31, "
                    "including the Windows 10/11 MAM/XPRESS-Huffman format.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_prefetch C:\\Windows\\Prefetch --csv pf.csv\n"
            "  windows_prefetch NOTEPAD.EXE-D8414F97.pf --json pf.json\n"
            "  windows_prefetch E:\\evidence\\collection --files-csv refs.csv\n"
        ),
    )
    p.add_argument("paths", nargs="*", metavar="PATH",
                   help=".pf file(s) or a directory to search")
    p.add_argument("--version", action="version",
                   version=f"windows_prefetch {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--csv", metavar="FILE", type=Path,
                   help="one summary row per prefetch file")
    p.add_argument("--files-csv", metavar="FILE", type=Path,
                   help="one row per (prefetch, referenced file)")
    p.add_argument("--json", metavar="FILE", type=Path)
    p.add_argument("--jsonl", metavar="FILE", type=Path)
    p.add_argument("--no-recurse", action="store_true")
    p.add_argument("--no-native", action="store_true",
                   help="always use the pure-Python decompressor")
    p.add_argument("--errors-only", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from windows_prefetch.gui import run_gui
        return run_gui([str(x) for x in (args.paths or [])])
    if args.no_native:
        os.environ["WINDOWS_PREFETCH_NO_NATIVE"] = "1"

    ctx = tracelib.context(args, "windows_prefetch", __version__)
    try:
        ctx.limits.check_paths([str(x) for x in _iter_pf_paths(args.paths, not args.no_recurse)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for _x in _iter_pf_paths(args.paths, not args.no_recurse):
        ctx.add_input(str(_x))

    items: list[PrefetchFile] = []
    for path in _iter_pf_paths(args.paths, not args.no_recurse):
        items.append(parse_file(path))

    items.sort(key=lambda pf: (
        pf.last_run.timestamp() if pf.last_run else 0.0, pf.executable
    ), reverse=True)

    if args.errors_only:
        items = [pf for pf in items if pf.parse_error]

    errors = sum(1 for pf in items if pf.parse_error)
    ok = [pf for pf in items if not pf.parse_error]

    wrote = []
    if args.csv:
        write_summary_csv(items, args.csv); wrote.append(str(args.csv))
    if args.files_csv:
        write_files_csv(ok, args.files_csv); wrote.append(str(args.files_csv))
    if args.json:
        write_json(items, args.json); wrote.append(str(args.json))
    if args.jsonl:
        write_jsonl(items, args.jsonl); wrote.append(str(args.jsonl))

    if errors:
        ctx.warn("partial", "parse-error", f"{errors} record(s) / file(s) failed to parse")
    _mpath = ctx.finish(outputs=[args.csv, getattr(args, 'files_csv', None), args.json, args.jsonl])
    if not args.quiet:
        print(render_table(items))

    print(f"windows_prefetch {__version__}: {len(ok)} parsed, {errors} error(s)",
          file=sys.stderr)
    for w in wrote:
        print(f"  wrote {w}", file=sys.stderr)

    return 1 if errors and not ok else 0


if __name__ == "__main__":
    raise SystemExit(main())
