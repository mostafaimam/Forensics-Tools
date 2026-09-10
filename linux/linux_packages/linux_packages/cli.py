from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from linux_packages import __version__, tracelib
from linux_packages.analyze import analyze
from linux_packages.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
# dpkg / dnf write UTC; apt history and yum text logs are local wall-clock
_TZ = {"dpkg": "utc-native", "dnf": "utc-native",
       "apt": "assumed-utc", "yum": "assumed-utc"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_packages",
        description="Reconstruct the package install / upgrade / remove "
                    "timeline from the package-manager logs under a mounted "
                    "image or a live root: dpkg.log, apt history.log, the "
                    "dnf / yum text logs and the dnf history.sqlite. Each "
                    "event is (time, action, package, version, from-version, "
                    "arch, source, requested-by, command). Flags build "
                    "toolchains, offensive / recon tooling, tunnel clients, "
                    "anti-forensic utilities, downgrades, manual out-of-repo "
                    ".deb installs and package ops run from a download pipe. "
                    "Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_packages /mnt/evidence\n"
                "  linux_packages / --csv packages.csv\n"
                "  linux_packages /mnt/img --notable-only --min-severity high\n"
                "  linux_packages /mnt/img --source apt --action install\n"
                "  linux_packages /var/log/dpkg.log --grep openssh\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="filesystem root(s) to walk, or individual log files")
    p.add_argument("--version", action="version",
                   version=f"linux_packages {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--source", choices=["dpkg", "apt", "dnf", "yum"],
                   action="append", help="only this log source (repeatable)")
    p.add_argument("--action",
                   help="only this action (install / upgrade / remove / ...)")
    p.add_argument("--grep", metavar="REGEX",
                   help="match package / version / command")
    p.add_argument("--since", metavar="YYYY-MM-DD",
                   help="only events on or after this date (UTC)")
    p.add_argument("--until", metavar="YYYY-MM-DD",
                   help="only events on or before this date (UTC)")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from linux_packages.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one path is required (or use --gui)")
    missing = [p for p in a.paths if not p.exists()]
    if missing:
        for p in missing:
            print(f"not found: {p}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "linux_packages", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = analyze(strpaths)
    for f in res.files_seen:
        ctx.add_input(f)
    for e in res.errors:
        ctx.error("parse-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    src = set(a.source) if a.source else None

    rows = []
    for ev in res.events:
        r = row(ev)
        if src and r["source"] not in src:
            continue
        if a.action and r["action"] != a.action:
            continue
        if a.since and (not r["ts"] or r["ts"][:10] < a.since):
            continue
        if a.until and (not r["ts"] or r["ts"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                f"{r['package']} {r['version']} {r['from_version']} "
                f"{r['command']}"):
            continue
        rows.append(r)

    tz = "mixed"
    srcs = {r["source"] for r in rows}
    if len(srcs) == 1:
        tz = _TZ.get(next(iter(srcs)), "assumed-utc")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz=tz)
    if a.json:
        tracelib.write_json(rows, a.json, ctx, confidence="high", tz=tz)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.findings), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    by = ", ".join(f"{k}:{v}" for k, v in sorted(res.sources.items()))
    print(f"linux_packages: {len(res.events)} event(s) from {res.files} "
          f"file(s) [{by}] -> {len(rows)} shown, {fl} flagged",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    for f in res.findings:
        print(f"  * {f}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
