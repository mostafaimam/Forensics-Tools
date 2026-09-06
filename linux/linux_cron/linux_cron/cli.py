from __future__ import annotations

import argparse
import sys
from pathlib import Path

from linux_cron import __version__
from linux_cron.collect import collect_file, collect_root, guess_kind
from linux_cron.cronexpr import CronError
from linux_cron.cronexpr import parse as parse_expr
from linux_cron.output import job_row, render_table, write_csv, write_json

_ORDER = {s: i for i, s in enumerate(
    ["system-crontab", "cron.d", "user-crontab", "run-parts", "anacron",
     "at", "systemd-timer"])}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_cron",
        description="Scheduled-execution inventory for Linux: system and user "
                    "crontabs, /etc/cron.d, cron.{hourly,daily,weekly,monthly}, "
                    "anacrontab, at jobs and systemd timers -> one normalised "
                    "row per job, with a plain-language schedule and a "
                    "suspicious-entry flag.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  linux_cron /                       # the live host\n"
            "  linux_cron /mnt/image --csv cron.csv\n"
            "  linux_cron --notable-only /mnt/image\n"
            "  linux_cron --file /etc/cron.d/mdadm\n"
            "  linux_cron --explain '*/5 9-17 * * mon-fri'\n"
        ),
    )
    p.add_argument("root", nargs="?", type=Path,
                   help="filesystem root to scan (e.g. / or a mounted image)")
    p.add_argument("--version", action="version",
                   version=f"linux_cron {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--file", type=Path, action="append", default=[],
                   metavar="PATH",
                   help="parse a single crontab / .timer / at-job file "
                        "(repeatable); type guessed from the path")
    p.add_argument("--as", dest="forced_kind",
                   choices=["crontab", "cron.d", "user-crontab", "anacrontab",
                            "at", "timer"],
                   help="force the file type for --file")
    p.add_argument("--explain", metavar="EXPR",
                   help="describe a 5-field cron expression and exit")
    p.add_argument("--source", type=lambda s: {x.strip() for x in s.split(",")},
                   metavar="S,S",
                   help="keep only these sources (systemd-timer, cron.d, ...)")
    p.add_argument("--user", help="keep only jobs running as this user")
    p.add_argument("--notable-only", action="store_true",
                   help="only jobs with at least one suspicious-entry flag")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from linux_cron.gui import run_gui
        return run_gui(([str(args.root)] if args.root else []))

    if args.explain:
        try:
            print(parse_expr(args.explain).describe())
            return 0
        except CronError as e:
            print(f"bad expression: {e}", file=sys.stderr)
            return 2

    jobs = []
    if args.file:
        for f in args.file:
            if not f.exists():
                print(f"! not found: {f}", file=sys.stderr)
                continue
            kind = args.forced_kind or guess_kind(f)
            jobs += collect_file(f, kind)
    if args.root:
        if not args.root.exists():
            print(f"! not found: {args.root}", file=sys.stderr)
            return 2
        jobs += collect_root(args.root)
    if not args.file and not args.root:
        build_parser().print_help()
        return 2

    if args.source:
        jobs = [j for j in jobs if j.source in args.source]
    if args.user:
        jobs = [j for j in jobs if j.run_as == args.user
                or j.run_as == f"uid {args.user}"]
    if args.notable_only:
        jobs = [j for j in jobs if j.notable]

    jobs.sort(key=lambda j: (_ORDER.get(j.source, 9), j.file, j.line_no))
    rows = [job_row(j) for j in jobs]

    if args.csv:
        write_csv(rows, args.csv)
    if args.json:
        write_json(rows, args.json)
    if not args.quiet and not (args.csv or args.json):
        print(render_table(rows))

    flagged = sum(1 for j in jobs if j.notable)
    errored = sum(1 for j in jobs if j.error)
    print(f"linux_cron {__version__}: {len(jobs)} job(s), {flagged} flagged"
          + (f", {errored} with parse errors" if errored else ""),
          file=sys.stderr)
    return 0 if jobs else 1


if __name__ == "__main__":
    raise SystemExit(main())
