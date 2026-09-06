from __future__ import annotations

import argparse
import getpass
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from acquisition_collect import __version__
from acquisition_collect.collector import Collector, CollectOptions, DirSink, ZipSink
from acquisition_collect.hashing import SUPPORTED as HASH_ALGS
from acquisition_collect.logutil import setup_logging
from acquisition_collect.paths import current_os, detect_host_context
from acquisition_collect.readers import get_reader
from acquisition_collect.report import Report
from acquisition_collect.targets import TargetError, load_builtin

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?b?)\s*$", re.IGNORECASE)
_UNITS = {"": 1, "b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}


def parse_size(text: str) -> int:
    m = _SIZE_RE.match(text)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid size: {text!r}")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


def _csv_list(text: str) -> list[str]:
    return [p.strip() for p in text.split(",") if p.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="acquisition_collect",
        description="Targeted forensic triage collector (cross-platform).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  acquisition_collect --list-targets\n"
            "  acquisition_collect -d E:\\out --category FileSystem,EventLogs --backend vss\n"
            "  acquisition_collect -d /evidence --source /mnt/image_c --os windows\n"
            "  acquisition_collect -d E:\\out --targets windows-prefetch --container zip "
            "--hash md5,sha256\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"acquisition_collect {__version__}")

    g_info = p.add_argument_group("discovery")
    g_info.add_argument("--list-targets", action="store_true",
                        help="list available targets and exit")
    g_info.add_argument("--target-info", metavar="ID",
                        help="show details for one target and exit")
    g_info.add_argument("--all-os", action="store_true",
                        help="with --list-targets, show targets for every OS")

    g_sel = p.add_argument_group("selection")
    g_sel.add_argument("--targets", type=_csv_list, default=[], metavar="ID,ID",
                       help="only collect these target ids")
    g_sel.add_argument("--category", type=_csv_list, default=[], metavar="CAT,CAT",
                       help="only collect targets in these categories")
    g_sel.add_argument("--target-dir", action="append", default=[],
                       metavar="DIR", type=Path,
                       help="extra directory of .toml target definitions "
                            "(repeatable)")

    g_src = p.add_argument_group("source")
    g_src.add_argument("--source", metavar="ROOT", type=Path,
                       help="collect from a mounted image / volume root "
                            "instead of the live system")
    g_src.add_argument("--os", dest="os_override",
                       choices=["windows", "linux", "macos"],
                       help="treat the source as this OS (default: this host)")
    g_src.add_argument("--backend", choices=["live", "vss"], default="live",
                       help="read backend (default: live; 'vss' = Windows "
                            "Volume Shadow Copy for locked volume metadata)")

    g_out = p.add_argument_group("output")
    g_out.add_argument("-d", "--dest", metavar="DIR", type=Path,
                       help="destination directory for the collection")
    g_out.add_argument("--container", choices=["dir", "zip"], default="dir",
                       help="write files into a folder tree or a zip "
                            "(default: dir)")
    g_out.add_argument("--hash", dest="hashes", type=_csv_list,
                       default=["sha1"], metavar=",".join(HASH_ALGS),
                       help="hash algorithms to record (default: sha1)")
    g_out.add_argument("--max-size", type=parse_size, default=None,
                       metavar="SIZE",
                       help="skip files larger than SIZE (e.g. 500MB)")
    g_out.add_argument("--no-dedupe", action="store_true",
                       help="collect a file even if another target already did")
    g_out.add_argument("--follow-symlinks", action="store_true",
                       help="follow symlinks / reparse points (off by default)")
    g_out.add_argument("--dry-run", action="store_true",
                       help="enumerate and log, but copy nothing")

    g_log = p.add_argument_group("logging")
    g_log.add_argument("-v", "--verbose", action="store_true")
    g_log.add_argument("-q", "--quiet", action="store_true")
    g_log.add_argument("--examiner", default=getpass.getuser(),
                       help="examiner name recorded in run info")
    g_log.add_argument("--case", default="", help="case number / reference")
    return p


def _load_targets(args, log):
    try:
        ts = load_builtin(extra_dirs=list(args.target_dir))
    except TargetError as e:
        log.error("target load error: %s", e)
        raise SystemExit(2)
    return ts


def _cmd_list(args, ts) -> int:
    oses = ["windows", "linux", "macos"] if args.all_os else [
        args.os_override or current_os()
    ]
    for os_name in oses:
        rows = ts.for_os(os_name)
        print(f"\n== {os_name} ==  ({len(rows)} targets)")
        by_cat: dict[str, list] = {}
        for t in rows:
            by_cat.setdefault(t.category, []).append(t)
        for cat in sorted(by_cat):
            print(f"  [{cat}]")
            for t in sorted(by_cat[cat], key=lambda x: x.id):
                raw = " (needs --backend vss)" if t.needs_raw else ""
                print(f"    {t.id:<28} {t.name}{raw}")
    print()
    return 0


def _cmd_target_info(tid, ts) -> int:
    for t in ts.targets:
        if t.id.lower() == tid.lower():
            print(f"id          : {t.id}")
            print(f"name        : {t.name}")
            print(f"category    : {t.category}")
            print(f"os          : {', '.join(sorted(t.os))}")
            print(f"needs_raw   : {t.needs_raw}")
            print(f"description : {t.description}")
            print(f"source      : {t.source}")
            print("paths:")
            for ps in t.paths:
                flag = " [recursive]" if ps.recursive else ""
                print(f"  - {ps.path}{flag}")
                if ps.comment:
                    print(f"      # {ps.comment}")
            return 0
    print(f"no such target: {tid}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log = setup_logging(None, args.verbose and not args.quiet)
    if args.quiet:
        import logging
        for h in log.handlers:
            h.setLevel(logging.ERROR)

    ts = _load_targets(args, log)

    if args.target_info:
        return _cmd_target_info(args.target_info, ts)
    if args.list_targets:
        return _cmd_list(args, ts)

    if args.dest is None:
        log.error("a destination is required: pass -d/--dest DIR "
                  "(or use --list-targets)")
        return 2

    try:
        bad = [h for h in args.hashes if h.lower() not in HASH_ALGS]
        if bad:
            log.error("unsupported hash(es): %s (choose from %s)",
                      bad, ", ".join(HASH_ALGS))
            return 2

        os_name = args.os_override or current_os()
        source_root = str(args.source) if args.source else None
        if source_root and not Path(source_root).exists():
            log.error("source root does not exist: %s", source_root)
            return 2

        ctx = detect_host_context(source_root=source_root)
        try:
            selected = ts.select(os_name, ids=args.targets or None,
                                 categories=args.category or None)
        except TargetError as e:
            log.error("%s", e)
            return 2
        if not selected:
            log.error("no targets selected for os=%s", os_name)
            return 2

        needs_raw = [t.id for t in selected if t.needs_raw]
        if needs_raw and args.backend != "vss":
            log.warning("these targets need raw volume access and will likely "
                        "fail without --backend vss: %s", ", ".join(needs_raw))

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        host = platform.node() or "host"
        run_name = f"acquisition_collect_{host}_{stamp}"
        run_dir = args.dest / run_name
        run_dir.mkdir(parents=True, exist_ok=True)

        log = setup_logging(run_dir / "acquisition_collect_console.log",
                            args.verbose and not args.quiet)
        report = Report(run_dir)

        opts = CollectOptions(
            hashes=tuple(h.lower() for h in args.hashes),
            max_bytes=args.max_size,
            dedupe=not args.no_dedupe,
            follow_symlinks=args.follow_symlinks,
            dry_run=args.dry_run,
        )

        if args.container == "zip":
            sink = ZipSink(run_dir / "collection.zip", "collection")
        else:
            sink = DirSink(run_dir, "collection")

        report.write_runinfo({
            "tool": "acquisition_collect",
            "version": __version__,
            "examiner": args.examiner,
            "case": args.case,
            "host": host,
            "host_platform": platform.platform(),
            "collection_os": os_name,
            "source_root": source_root,
            "backend": args.backend,
            "container": args.container,
            "hashes": list(opts.hashes),
            "targets": [t.id for t in selected],
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "command_line": " ".join(sys.argv),
        })

        log.info("acquisition_collect %s  |  os=%s  backend=%s  targets=%d",
                 __version__, os_name, args.backend, len(selected))
        if args.dry_run:
            log.info("DRY RUN - no files will be copied")

        try:
            reader = get_reader(args.backend)
        except Exception as e:  # noqa: BLE001
            log.error("cannot init backend %s: %s", args.backend, e)
            return 2

        from acquisition_collect.readers.base import ReadError

        try:
            with reader:
                Collector(ctx, reader, sink, report, opts, log).run(selected)
        except ReadError as e:
            log.error("backend '%s' unavailable: %s", args.backend, e)
            sink.close()
            report.finalise(extra={"Output": str(run_dir),
                                   "Aborted": f"backend error: {e}"})
            return 2
        finally:
            sink.close()

        summary = report.finalise(extra={
            "Output": str(run_dir),
            "Backend": args.backend,
            "Container": args.container,
        })
        print("\n" + summary)
        return 1 if report.stats.errors and report.stats.files_collected == 0 else 0

    except KeyboardInterrupt:
        log.error("interrupted by user")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
