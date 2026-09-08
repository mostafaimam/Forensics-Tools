from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from linux_bashhist import __version__, tracelib
from linux_bashhist.collect import collect_file, collect_root
from linux_bashhist.output import COLUMNS, entry_row, render_table

_MIN = datetime(1, 1, 1, tzinfo=timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_bashhist",
        description="Recover and merge shell / REPL history across all users "
                    "(bash, zsh, fish, sh, plus python / mysql / psql / sqlite "
                    "/ node / redis), parse per-shell timestamps, and flag "
                    "attacker-looking commands.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  linux_bashhist /                       # the live host\n"
            "  linux_bashhist /mnt/image --csv hist.csv\n"
            "  linux_bashhist /mnt/image --notable-only\n"
            "  linux_bashhist --file /home/bob/.bash_history --user bob\n"
            "  linux_bashhist /mnt/image --grep 'wget|curl' --user root\n"
        ),
    )
    p.add_argument("root", nargs="?", type=Path,
                   help="filesystem root to scan (/ or a mounted image)")
    p.add_argument("--version", action="version",
                   version=f"linux_bashhist {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--file", type=Path, action="append", default=[],
                   metavar="PATH", help="parse a single history file (repeatable)")
    p.add_argument("--user", help="user label for --file / filter for a scan")
    p.add_argument("--shell", type=_csv, help="keep only these shells")
    p.add_argument("--grep", metavar="REGEX",
                   help="keep only commands matching this regex (case-insensitive)")
    p.add_argument("--notable-only", action="store_true",
                   help="only commands with at least one heuristic flag")
    p.add_argument("--with-notes", action="store_true",
                   help="also show tampering-marker rows (empty/out-of-order)")
    p.add_argument("--from", dest="dt_from")
    p.add_argument("--to", dest="dt_to")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _csv(s: str):
    return {x.strip() for x in s.split(",") if x.strip()}


def _key(s: str) -> str:
    return s.replace("Z", "").replace("T", " ")[:19]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from linux_bashhist.gui import run_gui
        return run_gui(([str(args.root)] if args.root else []))
    grep = re.compile(args.grep, re.IGNORECASE) if args.grep else None
    dt_from = _key(args.dt_from) if args.dt_from else None
    dt_to = _key(args.dt_to) if args.dt_to else None

    entries = []
    if args.file:
        for f in args.file:
            if not f.exists():
                print(f"! not found: {f}", file=sys.stderr)
                continue
            entries += list(collect_file(f, args.user))
    if args.root:
        if not args.root.exists():
            print(f"! not found: {args.root}", file=sys.stderr)
            return 2
        entries += list(collect_root(args.root))
    if not args.file and not args.root:
        build_parser().print_help()
        return 2

    ctx = tracelib.context(args, "linux_bashhist", __version__)
    _ins = list(args.file or []) + ([args.root] if args.root else [])
    try:
        ctx.limits.check_paths([str(x) for x in _ins])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for _x in _ins:
        ctx.add_input(str(_x))

    marker_rows = [e for e in entries if not e.command and e.note]
    cmd_rows = [e for e in entries if e.command]

    if args.user and args.root and not args.file:
        cmd_rows = [e for e in cmd_rows if e.user == args.user]
        marker_rows = [e for e in marker_rows if e.user == args.user]
    if args.shell:
        cmd_rows = [e for e in cmd_rows if e.shell in args.shell]
    if grep:
        cmd_rows = [e for e in cmd_rows if grep.search(e.command)]
    if args.notable_only:
        cmd_rows = [e for e in cmd_rows if e.notable]
    cmd_rows = [e for e in cmd_rows
               if _in_window(e.timestamp, dt_from, dt_to)]

    cmd_rows.sort(key=lambda e: (e.timestamp or _MIN, e.user, e.source_file,
                                 e.line_no))
    shown = list(cmd_rows)
    if args.with_notes:
        shown += marker_rows

    rows = [entry_row(e) for e in shown]
    if args.csv:
        tracelib.write_csv(rows, args.csv, COLUMNS, ctx,
                           confidence="high", tz="assumed-utc")
    if args.json:
        tracelib.write_json(rows, args.json, ctx,
                            confidence="high", tz="assumed-utc")
    if not args.quiet and not (args.csv or args.json):
        print(render_table(rows))

    flagged = sum(1 for e in cmd_rows if e.notable)
    dated = sum(1 for e in cmd_rows if e.timestamp)
    msg = (f"linux_bashhist {__version__}: {len(cmd_rows)} command(s), "
           f"{dated} timestamped, {flagged} flagged")
    if marker_rows:
        msg += f", {len(marker_rows)} tampering marker(s)"
    ctx.finish(outputs=[args.csv, args.json])
    print(msg, file=sys.stderr)
    return 0 if cmd_rows or marker_rows else 1


def _in_window(ts, dt_from, dt_to) -> bool:
    if ts is None:
        return not (dt_from or dt_to)
    iso = ts.strftime("%Y-%m-%d %H:%M:%S")
    if dt_from and iso < dt_from:
        return False
    if dt_to and iso > dt_to:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
