from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from recovery_metadata import __version__
from recovery_metadata.ntfs import NotNtfsError, NtfsVolume
from recovery_metadata.output import extract_tree, render_table, write_listing_csv

_HASHES = ("md5", "sha1", "sha256")


def _log(verbose: bool) -> logging.Logger:
    lg = logging.getLogger("recovery_metadata")
    lg.handlers.clear()
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG if verbose else logging.INFO)
    return lg


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recovery_metadata",
        description="Recover files from file-system metadata. v0.1 supports "
                    "NTFS: list every MFT entry (allocated and deleted) with "
                    "full paths and MACB times, and extract file content "
                    "including deleted-but-intact files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  recovery_metadata list  volume.raw --csv mft.csv\n"
            "  recovery_metadata list  disk.dd --offset 1048576 --deleted-only\n"
            "  recovery_metadata extract volume.raw -o recovered/ --deleted-only\n"
            "  recovery_metadata cat    volume.raw --entry 41573 > file.bin\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"recovery_metadata {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("image", type=Path, help="NTFS volume image or disk image")
    common.add_argument("--offset", type=int, default=0,
                        help="byte offset of the NTFS volume within the image")
    common.add_argument("-v", "--verbose", action="store_true")

    gp = sub.add_parser("gui", parents=[common], help="open the graphical entry list")
    lst = sub.add_parser("list", parents=[common], help="list MFT entries")
    lst.add_argument("--csv", type=Path, metavar="FILE")
    lst.add_argument("--deleted-only", action="store_true")
    lst.add_argument("--files-only", action="store_true")
    lst.add_argument("--max-table", type=int, default=200)
    lst.add_argument("-q", "--quiet", action="store_true")

    ext = sub.add_parser("extract", parents=[common],
                         help="extract file content to an output tree")
    ext.add_argument("-o", "--out", type=Path, required=True)
    ext.add_argument("--deleted-only", action="store_true")
    ext.add_argument("--hash", dest="hashes", default=["sha1"],
                     type=lambda s: s.split(","), metavar=",".join(_HASHES))

    cat = sub.add_parser("cat", parents=[common],
                         help="write one entry's data to stdout")
    cat.add_argument("--entry", type=int, required=True)
    return p


def _open(image: Path, offset: int) -> NtfsVolume:
    fh = open(image, "rb", buffering=1024 * 1024)
    return NtfsVolume(fh, offset)


def _filter(entries, deleted_only=False, files_only=False):
    for e in entries:
        if deleted_only and e.in_use:
            continue
        if files_only and e.is_directory:
            continue
        yield e


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log = _log(getattr(args, "verbose", False))

    if not args.image.exists():
        log.error("image not found: %s", args.image)
        return 2
    try:
        vol = _open(args.image, args.offset)
    except NotNtfsError as e:
        log.error("%s (try --offset to point at the NTFS partition)", e)
        return 2
    except OSError as e:
        log.error("cannot open image: %s", e)
        return 2

    log.info("NTFS volume: %d-byte clusters, %d MFT records, serial %016X",
             vol.boot.cluster_size, vol.record_count(), vol.boot.serial_number)

    if args.cmd == "gui":
        from recovery_metadata.gui import run_gui
        return run_gui([str(args.image)] if args.image else [])
    if args.cmd == "cat":
        target = None
        for e in vol.iter_entries():
            if e.number == args.entry:
                target = e
                break
        if target is None:
            log.error("entry %d not found", args.entry)
            return 2
        sys.stdout.buffer.write(vol.read_file(target))
        return 0

    entries = list(_filter(
        vol.iter_entries(include_unused=True),
        deleted_only=getattr(args, "deleted_only", False),
        files_only=getattr(args, "files_only", False),
    ))

    if args.cmd == "list":
        if args.csv:
            write_listing_csv(vol, entries, args.csv)
            log.info("wrote %s (%d rows)", args.csv, len(entries))
        if not args.quiet:
            print(render_table(vol, entries, args.max_table))
        deleted = sum(1 for e in entries if e.deleted)
        log.info("%d entries (%d deleted)", len(entries), deleted)
        return 0

    if args.cmd == "extract":
        bad = [h for h in args.hashes if h not in _HASHES]
        if bad:
            log.error("unsupported hash(es): %s", bad)
            return 2
        args.out.mkdir(parents=True, exist_ok=True)
        ok, failed = extract_tree(vol, entries, args.out,
                                  tuple(args.hashes), log)
        log.info("extracted %d file(s), %d failure(s) -> %s", ok, failed, args.out)
        return 0 if ok or not failed else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
