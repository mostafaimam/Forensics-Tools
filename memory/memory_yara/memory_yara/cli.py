from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_yara import __version__, tracelib
from memory_yara.collect import COLUMNS, scan_image

_STARTER_RULES = Path(__file__).parent / "rules" / "starter.yar"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_yara",
        description="Scan a memory image with YARA-style rules - a "
                    "bundled, from-scratch matcher for a practical subset "
                    "of the YARA rule language (text/hex/regex string "
                    "patterns, boolean and counting conditions). No "
                    "yara-python, no network access. v0.1 scans raw "
                    "physical memory only (no per-process/module "
                    "attribution yet).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  memory_yara MEMORY.DMP --rules mimikatz.yar\n"
                "  memory_yara MEMORY.DMP --starter-rules --csv hits.csv\n"))
    p.add_argument("image", nargs="?", type=Path,
                   help="a memory image (raw / LiME / ELF core / Windows "
                   "crash dump / bitmap)")
    p.add_argument("--rules", type=Path, help="a .yar rules file")
    p.add_argument("--starter-rules", action="store_true",
                   help="use the bundled starter ruleset instead of "
                   "--rules")
    p.add_argument("--version", action="version",
                   version=f"memory_yara {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_yara.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    rules_path = a.rules or (_STARTER_RULES if a.starter_rules else None)
    if not rules_path:
        build_parser().error("--rules PATH or --starter-rules is required")
    if not rules_path.exists():
        print(f"not found: {rules_path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_yara", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))
    ctx.add_input(str(rules_path))

    res = scan_image(str(a.image), str(rules_path))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            print(f"{r['rule']}  [{r['notable']}]  {r['string_ids']}")
            if r["description"]:
                print(f"  {r['description']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="high", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_yara: {len(res.rows)} rule match(es)", file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
