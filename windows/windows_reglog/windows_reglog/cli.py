from __future__ import annotations

import argparse
import sys
from pathlib import Path

from windows_reglog import __version__, tracelib
from windows_reglog.logfile import BaseBlock, RegLogError, parse_log
from windows_reglog.replay import replay_files


def _find_logs(primary: Path) -> list[Path]:
    out = []
    for suffix in (".LOG1", ".LOG2", ".LOG"):
        for cand in (primary.with_suffix(primary.suffix + suffix),
                     primary.with_suffix(suffix)):
            if cand.exists() and cand not in out:
                out.append(cand)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_reglog",
        description="Replay Windows registry transaction logs (.LOG1 / .LOG2) "
                    "into a dirty hive so downstream tools see a clean hive.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_reglog SYSTEM -o SYSTEM.clean\n"
            "  windows_reglog NTUSER.DAT --log NTUSER.DAT.LOG1 NTUSER.DAT.LOG2 -o out.dat\n"
            "  windows_reglog --info SOFTWARE\n"
        ),
    )
    p.add_argument("hive", type=Path, nargs="?", help="the primary hive")
    p.add_argument("--version", action="version",
                   version=f"windows_reglog {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--log", nargs="+", type=Path, metavar="LOG",
                   help="transaction log(s) (default: auto-find beside the hive)")
    p.add_argument("-o", "--out", type=Path, help="write the recovered hive here")
    p.add_argument("--info", action="store_true",
                   help="show sequence numbers and log entries, do not write")
    p.add_argument("--no-verify", action="store_true",
                   help="skip Marvin32 hash verification of log entries")
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from windows_reglog.gui import run_gui
        return run_gui(([str(args.hive)] if args.hive else []))
    if args.hive is None:
        build_parser().error("a hive path is required (or use --gui)")
    if not args.hive.exists():
        print(f"hive not found: {args.hive}", file=sys.stderr)
        return 2

    logs = list(args.log) if args.log else _find_logs(args.hive)
    missing = [p for p in logs if not p.exists()]
    if missing:
        print(f"log not found: {missing}", file=sys.stderr)
        return 2

    ctx = tracelib.context(args, "windows_reglog", __version__)
    try:
        ctx.limits.check_paths([str(args.hive)] + [str(p) for p in logs])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(args.hive))
    for _lp in logs:
        ctx.add_input(str(_lp))

    try:
        base = BaseBlock.parse(args.hive.read_bytes())
    except RegLogError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.info:
        print(f"hive           : {args.hive}")
        print(f"  file type    : {'transaction log' if base.is_log else 'primary hive'}")
        print(f"  sequences    : primary={base.primary_sequence} "
              f"secondary={base.secondary_sequence} "
              f"({'DIRTY' if base.is_dirty else 'clean'})")
        print(f"  hive bins    : {base.hive_bins_size} bytes")
        for lp in logs:
            try:
                lb, entries = parse_log(lp.read_bytes())
            except RegLogError as e:
                print(f"  {lp.name}: {e}")
                continue
            seqs = [e.sequence for e in entries]
            bad = sum(1 for e in entries if not e.hash1_ok)
            print(f"  {lp.name}: {len(entries)} entr(y|ies), "
                  f"seq {min(seqs) if seqs else '-'}..{max(seqs) if seqs else '-'}, "
                  f"{bad} hash mismatch, "
                  f"{sum(len(e.pages) for e in entries)} dirty pages")
        if not logs:
            print("  (no transaction logs found beside the hive)")
        return 0

    if not base.is_dirty:
        print("hive is already clean - nothing to replay", file=sys.stderr)
        if args.out:
            args.out.write_bytes(args.hive.read_bytes())
        return 0

    if not logs:
        print("hive is DIRTY but no transaction logs were found "
              "(pass --log, or place .LOG1/.LOG2 beside the hive)",
              file=sys.stderr)
        return 2

    try:
        res = replay_files(args.hive, logs, verify=not args.no_verify)
    except RegLogError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"applied {len(res.applied_sequences)} log entr(y|ies) "
              f"(seq {res.applied_sequences[0] if res.changed else '-'}"
              f"..{res.applied_sequences[-1] if res.changed else '-'}), "
              f"{res.pages_written} pages / {res.bytes_written:,} bytes",
              file=sys.stderr)
        for note in res.notes:
            print(f"  ! {note}", file=sys.stderr)

    if args.out:
        args.out.write_bytes(res.recovered)
        print(f"  wrote {args.out}", file=sys.stderr)
    elif res.changed:
        print("(no -o given; recovered hive not written)", file=sys.stderr)

    for _n in res.notes:
        ctx.warn("partial", "replay-note", _n)
    ctx.finish(outputs=[args.out] if args.out else [])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
