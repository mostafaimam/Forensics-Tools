from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from linux_persistence import __version__, tracelib
from linux_persistence.output import COLUMNS, render, row
from linux_persistence.scan import scan

_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_persistence",
        description="One sweep for every userland persistence vector on a "
                    "mounted Linux image or a live root: shell rc / profile.d "
                    "/ environment, the dynamic loader (ld.so.preload / "
                    "ld.so.conf / LD_*), rc.local / init.d, update-motd.d, "
                    "xinetd / inetd, PAM modules, kernel-module autoload / "
                    "modprobe install lines, udev RUN / PROGRAM rules, "
                    "sudoers NOPASSWD / shell-capable rules and systemd "
                    "generators. One normalised finding per hit: mechanism, "
                    "path, payload line, mtime, verdict. Flags world-writable "
                    "configs, inline shells / cradles, encoded payloads and "
                    "loader hijacks. Pure standard library. (linux_cron and "
                    "linux_units do the full cron / unit job.)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_persistence /mnt/evidence\n"
                "  linux_persistence / --csv persistence.csv\n"
                "  linux_persistence /mnt/img --min-verdict medium\n"
                "  linux_persistence /mnt/img --mechanism sudoers,pam\n"))
    p.add_argument("root", nargs="?", type=Path,
                   help="filesystem root to sweep (mounted image or /)")
    p.add_argument("--version", action="version",
                   version=f"linux_persistence {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--mechanism", help="comma-separated list to include")
    p.add_argument("--grep", metavar="REGEX", help="match payload / path / why")
    p.add_argument("--min-verdict", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from linux_persistence.gui import run_gui
        return run_gui([str(a.root)] if a.root else [])
    if not a.root:
        build_parser().error("a filesystem root is required (or use --gui)")
    if not a.root.exists():
        print(f"not found: {a.root}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "linux_persistence", __version__)
    try:
        ctx.limits.check_paths([str(a.root)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = scan(str(a.root))
    for f in res.files_seen:
        ctx.add_input(f)
    for e in res.errors:
        ctx.error("scan-error", e)

    mechs = set(a.mechanism.split(",")) if a.mechanism else None
    grep = re.compile(a.grep, re.I) if a.grep else None

    rows = []
    for f in res.findings:
        if mechs and f.mechanism not in mechs:
            continue
        if a.min_verdict and _SEV[f.verdict] < _SEV[a.min_verdict]:
            continue
        r = row(f)
        if grep and not grep.search(" ".join((r["payload"], r["path"],
                                              r["why"]))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="heuristic", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(res), end="")

    ctx.finish(outputs=[a.csv, a.json])
    hi = sum(1 for r in rows if r["verdict"] == "high")
    print(f"linux_persistence: {len(res.findings)} finding(s) -> {len(rows)} "
          f"shown, {hi} high", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
