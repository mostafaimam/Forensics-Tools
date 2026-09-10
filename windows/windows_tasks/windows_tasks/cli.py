from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_tasks import __version__, tracelib
from windows_tasks.analyze import analyze
from windows_tasks.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_tasks",
        description="Parse Windows Scheduled Tasks from the on-disk task XML "
                    "(C:\\Windows\\System32\\Tasks\\**) and, when a SOFTWARE "
                    "hive is present, join the TaskCache\\{Tree,Tasks} "
                    "registry keys. One row per task: author, registration "
                    "date, triggers (plain language), principal (run-as SID, "
                    "run level, logon type), hidden / enabled flags, every "
                    "action (Exec command + arguments or a ComHandler CLSID), "
                    "and the TaskCache 'registered' / 'last run' timestamps. "
                    "Flags living-off-the-land binaries, user-writable / UNC "
                    "action paths, encoded PowerShell, hidden tasks, tasks "
                    "outside \\Microsoft\\Windows, SYSTEM-from-user-path, "
                    "ComHandler actions and registry-only / tree-missing "
                    "tasks. Pure standard library (regf parser vendored).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_tasks E:\\  (mounted image root)\n"
                "  windows_tasks C:\\Windows\\System32\\Tasks --csv t.csv\n"
                "  windows_tasks E:\\ --notable-only --min-severity high\n"
                "  windows_tasks E:\\ --grep 'powershell|mshta'\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="mounted-image root, a Tasks directory, or the "
                        "SOFTWARE hive's parent")
    p.add_argument("--version", action="version",
                   version=f"windows_tasks {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--enabled-only", action="store_true")
    p.add_argument("--hidden-only", action="store_true")
    p.add_argument("--grep", metavar="REGEX",
                   help="match task path / command / author / triggers")
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
        from windows_tasks.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one path is required (or use --gui)")
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_tasks", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = analyze(strpaths)
    for t in res.tasks:
        if t.source:
            ctx.add_input(t.source)
    if res.hive_file:
        ctx.add_input(res.hive_file)
    for e in res.errors:
        ctx.error("parse-error", e)
    if not res.hive_file:
        ctx.partial("no-software-hive",
                    "no SOFTWARE hive found; TaskCache timestamps and the "
                    "Tree / registry-only checks are unavailable")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for t in res.tasks:
        r = row(t)
        if a.enabled_only and r["enabled"] != "yes":
            continue
        if a.hidden_only and r["hidden"] != "yes":
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["task_path"], r["command_line"], r["author"],
                r["triggers"]))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_tasks: {len(res.tasks)} task(s) "
          f"({res.xml_files} XML, {res.cache_entries} TaskCache) -> "
          f"{len(rows)} shown, {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
