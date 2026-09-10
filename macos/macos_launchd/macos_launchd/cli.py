from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_launchd import __version__, tracelib
from macos_launchd import flags as _flags
from macos_launchd.collect import collect, sort_jobs

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["scope", "label", "filename", "program", "command_line", "run_as",
           "disabled", "run_at_load", "keep_alive", "triggers", "env",
           "stdout", "stderr", "mach_services", "world_writable", "severity",
           "source", "notable"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_launchd",
        description="Review every launchd job plist under a mounted macOS "
                    "volume or a live root: /Library/Launch{Daemons,Agents}, "
                    "~/Library/LaunchAgents and the Apple-shipped "
                    "/System/Library ones. One row per job: scope, label, "
                    "resolved program / argv, run-as user, triggers in plain "
                    "language (RunAtLoad / StartInterval / "
                    "StartCalendarInterval / WatchPaths / KeepAlive), the "
                    "disabled flag and the environment variables. Flags "
                    "programs in a writable path, inline shells / cradles, "
                    "DYLD_ injection, label / filename mismatch, Apple-label "
                    "masquerades and world-writable plists. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_launchd /Volumes/Macintosh\\ HD --csv launchd.csv\n"
                "  macos_launchd com.evil.plist --json j.json\n"
                "  macos_launchd /mnt/mac --notable-only --min-severity high\n"
                "  macos_launchd /mnt/mac --scope system-daemon "
                "--exclude-apple\n"))
    p.add_argument("path", type=Path,
                   help="a mounted macOS volume, a launchd dir, or a plist")
    p.add_argument("--version", action="version",
                   version=f"macos_launchd {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--scope", choices=["system-daemon", "system-agent",
                                       "user-agent", "apple"])
    p.add_argument("--exclude-apple", action="store_true",
                   help="drop the /System/Library Apple jobs")
    p.add_argument("--grep", metavar="REGEX",
                   help="match label / program / command / triggers")
    p.add_argument("--enabled-only", action="store_true")
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
        from macos_launchd.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_launchd", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.path))

    res = collect(str(a.path))
    for e in res.errors:
        ctx.error("plist-error", e)
    sort_jobs(res.jobs)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for j in res.jobs:
        r = j.row()
        r["severity"] = _flags.severity(j.notable)
        if a.scope and r["scope"] != a.scope:
            continue
        if a.exclude_apple and r["scope"] == "apple":
            continue
        if a.enabled_only and r["disabled"] == "yes":
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["label"], r["program"], r["command_line"], r["triggers"]))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="no-timezone")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="no-timezone")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            state = " (disabled)" if r["disabled"] else ""
            print(f"{r['scope']:<14} {r['label'] or r['filename']}{state}"
                  f"{mark}")
            if r["command_line"]:
                print(f"    run: {r['command_line']}")
            if r["triggers"]:
                print(f"    when: {r['triggers']}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_launchd: {res.files} plist(s) -> {len(res.jobs)} job(s) -> "
          f"{len(rows)} shown, {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
