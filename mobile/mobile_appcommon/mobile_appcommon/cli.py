from __future__ import annotations

import json
import sys
import argparse
from pathlib import Path

from mobile_appcommon import __version__, tracelib
from mobile_appcommon.collect import COLUMNS, decode_blob, decode_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mobile_appcommon",
        description="Generic inspector for the binary blob formats that "
                    "turn up throughout a mobile extraction: binary "
                    "property lists (with NSKeyedArchiver unwrapping) "
                    "and schemaless Protocol Buffers (wire-format "
                    "decode - no .proto schema needed, but string/bytes/"
                    "nested-message classification per field is a "
                    "best-effort guess; see the README). Point it at an "
                    "unknown BLOB column, a LevelDB value, or a cache "
                    "file directly.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  mobile_appcommon unknown.blob\n"
                "  mobile_appcommon --hex 0a0568656c6c6f\n"
                "  mobile_appcommon cached.plist --csv fields.csv\n"))
    p.add_argument("target", nargs="?", type=Path,
                   help="a file to decode")
    p.add_argument("--hex", help="decode an inline hex string instead of "
                   "a file")
    p.add_argument("--version", action="version",
                   version=f"mobile_appcommon {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from mobile_appcommon.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target and not a.hex:
        build_parser().error("a target file, --hex, or --gui is required")

    ctx = tracelib.context(a, "mobile_appcommon", __version__)
    if a.hex:
        try:
            data = bytes.fromhex(a.hex.strip())
        except ValueError as e:
            print(f"error: bad --hex value: {e}", file=sys.stderr)
            return 2
        res = decode_blob(data, source="<--hex>")
    else:
        if not a.target.exists():
            print(f"not found: {a.target}", file=sys.stderr)
            return 2
        try:
            ctx.limits.check_paths([str(a.target)])
        except tracelib.LimitExceeded as e:
            print(f"resource limit: {e}", file=sys.stderr)
            return 3
        ctx.add_input(str(a.target))
        res = decode_file(str(a.target))

    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        print(f"format: {res.fmt}", file=sys.stderr)
        for r in res.rows:
            print(f"{r['path']:<24} {r['value']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="no-timezone")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="medium", tz="no-timezone")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"mobile_appcommon: format={res.fmt}, {len(res.rows)} field(s)",
         file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
