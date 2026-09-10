from __future__ import annotations

import argparse
import sys
from pathlib import Path

from utilities_strings import __version__, tracelib
from utilities_strings.patterns import LIBRARY
from utilities_strings.strings import scan

COLUMNS = ["offset", "encoding", "length", "text", "category", "match"]


def _num(s: str) -> int:
    return int(str(s), 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="utilities_strings",
        description="Extract ASCII and UTF-16 (LE/BE) strings from a file, "
                    "image or device with byte offsets, and classify each "
                    "against a built-in forensic pattern library (URLs, "
                    "emails, IPs, paths, registry keys, tokens, wallet "
                    "addresses, credit cards, offensive-tooling markers, "
                    "...). Filter by --category / --pattern / --grep.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  utilities_strings suspicious.bin --min-len 6\n"
                "  utilities_strings disk.raw --category url,email,btc "
                "--csv iocs.csv\n"
                "  utilities_strings pagefile.sys --classified --json c.json\n"
                "  utilities_strings \\\\.\\C: --grep mimikatz --hex\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="file / image / device path")
    p.add_argument("--version", action="version",
                   version=f"utilities_strings {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--list-patterns", action="store_true",
                   help="print the built-in pattern names and exit")
    p.add_argument("-n", "--min-len", type=int, default=4)
    p.add_argument("-e", "--encoding", default="ascii,utf-16le",
                   help="comma list of ascii,utf-16le,utf-16be "
                   "(default ascii,utf-16le)")
    p.add_argument("--hex", action="store_true",
                   help="print offsets in hexadecimal")
    p.add_argument("--start", type=_num, default=0, metavar="OFF")
    p.add_argument("--end", type=_num, default=None, metavar="OFF")
    p.add_argument("--category", metavar="A,B",
                   help="only strings matching these pattern categories")
    p.add_argument("--pattern", metavar="NAME",
                   help="alias for --category with a single name")
    p.add_argument("--classified", action="store_true",
                   help="only strings that match at least one pattern")
    p.add_argument("--grep", metavar="REGEX")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.list_patterns:
        for name in sorted(LIBRARY):
            print(name)
        return 0
    if a.gui:
        from utilities_strings.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    is_device = a.target.startswith(("\\\\.\\", "/dev/"))
    if not is_device and not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    cats = None
    if a.category or a.pattern:
        raw = (a.category or a.pattern)
        cats = [c.strip() for c in raw.split(",") if c.strip()]
        bad = [c for c in cats if c not in LIBRARY]
        if bad:
            build_parser().error(f"unknown pattern(s): {', '.join(bad)}. "
                                 f"See --list-patterns.")
    encs = tuple(e.strip() for e in a.encoding.split(",") if e.strip())

    ctx = tracelib.context(a, "utilities_strings", __version__)
    if not is_device:
        try:
            ctx.limits.check_paths([a.target])
        except tracelib.LimitExceeded as e:
            print(f"resource limit: {e}", file=sys.stderr)
            return 3
    ctx.add_input(a.target)

    prog = None
    if not a.quiet:
        def prog(done, total):  # noqa: E306
            pct = f"{100 * done // total}%" if total else str(done)
            sys.stderr.write(f"\r  scanning {pct}")
            sys.stderr.flush()

    rows = []
    try:
        it = scan(a.target, min_len=a.min_len, encodings=encs, start=a.start,
                  end=a.end, grep=a.grep, categories=cats,
                  classified_only=a.classified, limit=a.limit, progress=prog)
        for hit in it:
            r = hit.row(a.hex)
            rows.append(r)
            if not a.quiet and not (a.csv or a.json):
                tag = f"  [{r['category']}]" if r["category"] else ""
                print(f"{r['offset']}\t{r['encoding']}\t{r['text']}{tag}")
    except PermissionError:
        print(f"error: cannot read {a.target} (locked / needs admin; try a "
              f"volume-shadow copy or an image)", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    classed = sum(1 for r in rows if r["category"])
    print(f"utilities_strings: {len(rows)} string(s), {classed} classified",
          file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
