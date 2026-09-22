from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_consoles import __version__, tracelib
from memory_consoles.collect import COLUMNS, scan_image


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_consoles",
        description="Best-effort console-host process discovery and "
                    "command-line string carving from a Windows memory "
                    "image. CONSOLE_INFORMATION's internal layout is "
                    "undocumented and version-drifted with no reliable "
                    "reference this project has - so this does NOT "
                    "decode console/history-buffer structures. Instead "
                    "it reports which conhost.exe/cmd.exe/powershell."
                    "exe/pwsh.exe processes were present (exact-name "
                    "match, not offset-guessed), plus generic printable "
                    "text that looks command-line-shaped, carved from "
                    "anywhere in the image - the two signals are not "
                    "correlated with each other. See the README.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  memory_consoles MEMORY.DMP --csv rows.csv\n")
    p.add_argument("image", nargs="?", type=Path)
    p.add_argument("--version", action="version",
                   version=f"memory_consoles {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--no-carve", action="store_true",
                   help="skip string carving, only report processes")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_consoles.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_consoles", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))

    res = scan_image(str(a.image), carve_strings=not a.no_carve)
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            print(f"{r['kind']:<14} {r['value']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="low", tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="low", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_consoles: {len(res.rows)} row(s)", file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
