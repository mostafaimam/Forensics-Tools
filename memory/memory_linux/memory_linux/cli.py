from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_linux import __version__, tracelib
from memory_linux.collect import COLUMNS, scan_image


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_linux",
        description="Best-effort Linux memory-image process-list "
                    "recovery. task_struct has no stable cross-version "
                    "signature the way Windows kernel objects have a "
                    "pool tag, so this follows the same "
                    "examiner-supplies-the-missing-piece pattern "
                    "memory_hashdump uses: with --profile (a small "
                    "JSON naming this kernel build's direct-map base, "
                    "init_task VA, and tasks/comm/pid field offsets), "
                    "performs a genuine, verifiable tasks-list walk. "
                    "Without one, falls back to a much weaker "
                    "heuristic comm-string carve - see the README.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  memory_linux linux.mem --profile "
              "kernel.json --csv procs.csv\n")
    p.add_argument("image", nargs="?", type=Path)
    p.add_argument("--profile", type=Path,
                   help="JSON: direct_map_base, init_task_va, "
                   "tasks_offset, comm_offset, pid_offset")
    p.add_argument("--version", action="version",
                   version=f"memory_linux {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_linux.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    if a.profile and not a.profile.exists():
        print(f"profile not found: {a.profile}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_linux", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))

    res = scan_image(str(a.image),
                     profile_path=str(a.profile) if a.profile else None)
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            print(f"{r['method']:<16} pid={r['pid']!s:<8} {r['comm']}")

    confidence = "high" if a.profile else "low"
    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence=confidence, tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence=confidence, tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_linux: {len(res.rows)} row(s)", file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
