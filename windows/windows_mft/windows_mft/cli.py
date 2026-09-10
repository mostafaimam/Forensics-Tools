from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from windows_mft import __version__, tracelib
from windows_mft.ntfs import iter_usn
from windows_mft.ntfs.mft import open_mft
from windows_mft.output import (
    render_mft_table,
    write_bodyfile,
    write_mft_csv,
    write_mft_json,
    write_usn_csv,
    write_usn_json,
)


def _log(verbose: bool) -> logging.Logger:
    lg = logging.getLogger("windows_mft")
    lg.handlers.clear()
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG if verbose else logging.INFO)
    return lg


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_mft",
        description="Parse the NTFS $MFT and the $UsnJrnl:$J change journal. "
                    "Full timeline, ADS listing, and $SI/$FN timestamp-anomaly "
                    "(timestomping) detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_mft mft  $MFT --csv mft.csv\n"
            "  windows_mft mft  volume.raw --offset 1048576 --deleted-only\n"
            "  windows_mft mft  $MFT --timestomped-only --csv suspicious.csv\n"
            "  windows_mft usn  '$J' --csv usn.csv\n"
            "  windows_mft cat  volume.raw --entry 5312 --stream Zone.Identifier\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"windows_mft {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mft", help="parse an $MFT (file) or NTFS volume image")
    m.add_argument("source", type=Path)
    m.add_argument("--offset", type=int, default=0,
                   help="byte offset of the NTFS volume (when SOURCE is a "
                        "disk/volume image rather than an extracted $MFT)")
    m.add_argument("--csv", type=Path)
    m.add_argument("--json", type=Path)
    m.add_argument("--bodyfile", type=Path, help="bodyfile format ($SI times)")
    m.add_argument("--deleted-only", action="store_true")
    m.add_argument("--files-only", action="store_true")
    m.add_argument("--timestomped-only", action="store_true")
    m.add_argument("--no-system", action="store_true",
                   help="skip the reserved system files (entries 0-15)")
    m.add_argument("--max-table", type=int, default=200)
    m.add_argument("-q", "--quiet", action="store_true")
    m.add_argument("-v", "--verbose", action="store_true")

    u = sub.add_parser("usn", help="parse a $UsnJrnl:$J stream")
    u.add_argument("source", type=Path, help="the $J data-stream file")
    u.add_argument("--csv", type=Path)
    u.add_argument("--json", type=Path)
    u.add_argument("--reason", type=lambda s: [x.strip().upper() for x in s.split(",")],
                   default=None, metavar="R,R",
                   help="keep only records with one of these reason flags")
    u.add_argument("-q", "--quiet", action="store_true")

    c = sub.add_parser("cat", help="write one entry's data stream to stdout")
    c.add_argument("source", type=Path)
    c.add_argument("--offset", type=int, default=0)
    c.add_argument("--entry", type=int, required=True)
    c.add_argument("--stream", default="", help="ADS name (default: unnamed)")

    sub.add_parser("gui", help="open the graphical $MFT browser")
    tracelib.add_arguments(p)
    return p


def _cmd_mft(args, log) -> int:
    ctx = tracelib.context(args, "windows_mft", __version__)
    try:
        ctx.limits.check_paths([str(args.source)])
    except tracelib.LimitExceeded as e:
        log.error("resource limit: %s", e)
        return 3
    ctx.add_input(str(args.source))
    try:
        mft = open_mft(args.source, args.offset)
    except ValueError as e:
        log.error("not an NTFS volume and not a recognisable $MFT: %s", e)
        return 2
    except OSError as e:
        log.error("cannot open %s: %s", args.source, e)
        return 2

    log.info("%d MFT records", mft.record_count())
    entries = []
    for e in mft.iter_entries(include_deleted=True,
                              include_system=not args.no_system):
        if args.deleted_only and e.in_use:
            continue
        if args.files_only and e.is_directory:
            continue
        if args.timestomped_only and not e.timestomp.any:
            continue
        entries.append(e)

    if args.csv:
        write_mft_csv(mft, entries, args.csv)
        log.info("wrote %s (%d rows)", args.csv, len(entries))
    if args.json:
        write_mft_json(mft, entries, args.json)
    if args.bodyfile:
        write_bodyfile(mft, entries, args.bodyfile)
    if not args.quiet:
        print(render_mft_table(mft, entries, args.max_table))
    deleted = sum(1 for e in entries if e.deleted)
    stomped = sum(1 for e in entries if e.timestomp.any)
    log.info("%d entries (%d deleted, %d with timestamp anomalies)",
             len(entries), deleted, stomped)
    ctx.finish(outputs=[getattr(args, 'csv', None), getattr(args, 'json', None), getattr(args, 'bodyfile', None), getattr(args, 'out', None)])
    return 0


def _cmd_usn(args, log) -> int:
    ctx = tracelib.context(args, "windows_mft", __version__)
    try:
        ctx.limits.check_paths([str(args.source)])
    except tracelib.LimitExceeded as e:
        log.error("resource limit: %s", e)
        return 3
    ctx.add_input(str(args.source))
    try:
        data = args.source.read_bytes()
    except OSError as e:
        log.error("cannot read %s: %s", args.source, e)
        return 2
    records = list(iter_usn(data))
    if args.reason:
        want = set(args.reason)
        records = [r for r in records if want & set(r.reason_names())]
    records.sort(key=lambda r: r.usn)
    if args.csv:
        write_usn_csv(records, args.csv)
        log.info("wrote %s (%d rows)", args.csv, len(records))
    if args.json:
        write_usn_json(records, args.json)
    if not args.quiet and not (args.csv or args.json):
        for r in records[:200]:
            from windows_mft.ntfs.attributes import iso_utc
            print(f"{iso_utc(r.timestamp):27} {r.usn:>12} {r.name:40} "
                  f"{'; '.join(r.reason_names())}")
    log.info("%d USN records", len(records))
    ctx.finish(outputs=[getattr(args, 'csv', None), getattr(args, 'json', None), getattr(args, 'bodyfile', None), getattr(args, 'out', None)])
    return 0


def _cmd_cat(args, log) -> int:
    ctx = tracelib.context(args, "windows_mft", __version__)
    try:
        ctx.limits.check_paths([str(args.source)])
    except tracelib.LimitExceeded as e:
        log.error("resource limit: %s", e)
        return 3
    ctx.add_input(str(args.source))
    try:
        mft = open_mft(args.source, args.offset)
    except (ValueError, OSError) as e:
        log.error("%s", e)
        return 2
    target = None
    for e in mft.iter_entries():
        if e.number == args.entry:
            target = e
            break
    if target is None:
        log.error("entry %d not found", args.entry)
        return 2
    sys.stdout.buffer.write(mft.read_stream(target, args.stream))
    ctx.finish(outputs=[getattr(args, 'csv', None), getattr(args, 'json', None), getattr(args, 'bodyfile', None), getattr(args, 'out', None)])
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log = _log(getattr(args, "verbose", False))

    if args.cmd == "gui":
        from windows_mft.gui import run
        return run()

    if not args.source.exists():
        log.error("source not found: %s", args.source)
        return 2

    if args.cmd == "mft":
        return _cmd_mft(args, log)
    if args.cmd == "usn":
        return _cmd_usn(args, log)
    if args.cmd == "cat":
        return _cmd_cat(args, log)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
