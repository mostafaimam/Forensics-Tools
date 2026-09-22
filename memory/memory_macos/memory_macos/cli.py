from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_macos import __version__, tracelib
from memory_macos.collect import COLUMNS, scan_image


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_macos",
        description="Best-effort macOS (XNU) memory-image process-list "
                    "recovery. proc has no stable cross-version "
                    "signature, so this follows the same "
                    "examiner-supplies-the-missing-piece pattern "
                    "memory_linux uses: with --profile (a small JSON "
                    "naming this kernel build's direct-map base, "
                    "allproc's first proc pointer, and "
                    "p_list/p_comm/p_pid field offsets), walks XNU's "
                    "BSD LIST-based allproc chain (NULL-terminated, "
                    "unlike Linux's circular tasks list). Without one, "
                    "falls back to weak heuristic comm-string carving. "
                    "This project's lowest-confidence memory/ tool - "
                    "see the README.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  memory_macos macos.mem --profile "
              "kernel.json --csv procs.csv\n")
    p.add_argument("image", nargs="?", type=Path)
    p.add_argument("--profile", type=Path,
                   help="JSON: direct_map_base, allproc_first_va, "
                   "p_list_next_offset, p_comm_offset, p_pid_offset")
    p.add_argument("--version", action="version",
                   version=f"memory_macos {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_macos.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    if a.profile and not a.profile.exists():
        print(f"profile not found: {a.profile}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_macos", __version__)
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

    confidence = "medium" if a.profile else "low"
    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence=confidence, tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence=confidence, tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_macos: {len(res.rows)} row(s)", file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
