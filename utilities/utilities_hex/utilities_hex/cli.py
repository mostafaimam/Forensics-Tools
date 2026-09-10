from __future__ import annotations

import argparse
import sys
from pathlib import Path

from utilities_hex import __version__, tracelib
from utilities_hex.hexview import file_size, hexdump, read_region, search
from utilities_hex.interp import interpret


def _num(s: str) -> int:
    return int(str(s), 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="utilities_hex",
        description="Hex viewer + data interpreter. Dump a region of any "
                    "file / image / device; interpret the bytes at an "
                    "offset as ints (8-64, LE+BE), float / double, GUID, "
                    "RGB and every common timestamp encoding; or search "
                    "for hex / text / UTF-16 / regex and report offsets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  utilities_hex firmware.bin --offset 0x1000 --length 256\n"
                "  utilities_hex record.bin --at 0x18\n"
                "  utilities_hex disk.raw --search 'MZ' --kind text "
                "--limit 20\n"
                "  utilities_hex $MFT --search 'FILE0' --kind hex --csv "
                "hits.csv\n"))
    p.add_argument("target", nargs="?", type=str)
    p.add_argument("--version", action="version",
                   version=f"utilities_hex {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("-o", "--offset", type=_num, default=0)
    p.add_argument("-l", "--length", type=_num, default=256)
    p.add_argument("--width", type=int, default=16)
    p.add_argument("--at", type=_num, metavar="OFF",
                   help="interpret the bytes at this offset")
    p.add_argument("--search", metavar="TERM")
    p.add_argument("--kind", choices=["hex", "text", "utf16", "regex"],
                   default="text")
    p.add_argument("--start", type=_num, default=0)
    p.add_argument("--end", type=_num, default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from utilities_hex.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")
    is_device = a.target.startswith(("\\\\.\\", "/dev/"))
    if not is_device and not Path(a.target).exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "utilities_hex", __version__)
    if not is_device:
        try:
            ctx.limits.check_paths([a.target])
        except tracelib.LimitExceeded as e:
            print(f"resource limit: {e}", file=sys.stderr)
            return 3
    ctx.add_input(a.target)

    try:
        if a.search is not None:
            return _do_search(a, ctx)
        if a.at is not None:
            return _do_interpret(a, ctx)
        return _do_dump(a, ctx)
    except PermissionError:
        print(f"error: cannot read {a.target} (locked / needs admin)",
              file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def _do_dump(a, ctx) -> int:
    data = read_region(a.target, a.offset, a.length)
    if not a.quiet:
        print(hexdump(data, base=a.offset, width=a.width))
    ctx.finish()
    print(f"utilities_hex: {len(data)} byte(s) at {a.offset:#x} "
          f"(file size {file_size(a.target)})", file=sys.stderr)
    return 0 if data else 1


def _do_interpret(a, ctx) -> int:
    buf = read_region(a.target, max(0, a.at - 0), 32)
    info = interpret(buf, 0)
    info["offset"] = a.at
    info["offset_hex"] = f"{a.at:#x}"
    ts = info.pop("timestamps", {})
    if a.json:
        tracelib.write_json([{**info, **{f"ts_{k}": v
                                         for k, v in ts.items()}}],
                            a.json, ctx, confidence="high", tz="n/a")
    if a.csv:
        row = {**{k: v for k, v in info.items()},
               **{f"ts_{k}": v for k, v in ts.items()}}
        tracelib.write_csv([row], a.csv, list(row), ctx,
                           confidence="high", tz="n/a")
    if not a.quiet and not (a.csv or a.json):
        print(f"offset {a.at:#x} ({a.at})   bytes: {info.get('hex', '')}")
        for k, v in info.items():
            if k in ("offset", "offset_hex", "hex"):
                continue
            print(f"  {k:<14} {v}")
        if ts:
            print("  timestamps:")
            for k, v in ts.items():
                print(f"    {k:<14} {v}")
    ctx.finish(outputs=[a.csv, a.json])
    return 0


def _do_search(a, ctx) -> int:
    rows = []
    for off, matched, context in search(a.target, a.search, kind=a.kind,
                                        start=a.start, end=a.end,
                                        limit=a.limit):
        r = {"offset": off, "offset_hex": f"{off:#x}",
             "match_hex": matched.hex(" "),
             "context": "".join(chr(b) if 0x20 <= b < 0x7f else "."
                                for b in context)}
        rows.append(r)
        if not a.quiet and not (a.csv or a.json):
            print(f"{off:#010x}  {r['context']}")
    if a.csv:
        tracelib.write_csv(rows, a.csv,
                           ["offset", "offset_hex", "match_hex", "context"],
                           ctx, confidence="high", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx, confidence="high", tz="n/a")
    ctx.finish(outputs=[a.csv, a.json])
    print(f"utilities_hex: {len(rows)} hit(s) for {a.kind} search",
          file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
