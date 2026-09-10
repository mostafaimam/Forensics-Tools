from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mounting_partitions import __version__, tracelib
from mounting_partitions.analyze import analyze, _hsize

COLUMNS = ["index", "scheme", "start_lba", "start_offset", "end_offset",
           "size_bytes", "size", "type", "type_code", "label", "bootable",
           "filesystem", "note"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mounting_partitions",
        description="Map the partition layout of a disk image (raw / split / "
                    "EWF / VHD / VMDK, or an nbd:// URL). Parses the MBR "
                    "(including extended / logical partitions) and the GPT, "
                    "and by peeking at the first sectors of each slice "
                    "reports the filesystem or container actually present "
                    "(NTFS / FAT / exFAT / ext2-4 / XFS / Btrfs / APFS / "
                    "HFS+ / LVM2 / LUKS / BitLocker / swap / ISO9660). Gaps "
                    "and overlaps are shown. Never mounts anything - "
                    "read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  mounting_partitions disk.raw\n"
                "  mounting_partitions evidence.E01 --json layout.json\n"
                "  mounting_partitions nbd://127.0.0.1:10809/disk --csv p.csv\n"))
    p.add_argument("image", type=Path, nargs="?",
                   help="the disk image (or nbd:// URL)")
    p.add_argument("--version", action="version",
                   version=f"mounting_partitions {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--format", dest="fmt",
                   choices=["raw", "ewf", "vhd", "vhdx", "vmdk", "nbd"],
                   help="force the container format instead of sniffing")
    p.add_argument("--sector", type=int, default=512,
                   help="logical sector size (default 512)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from mounting_partitions.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if not a.image:
        build_parser().error("an image is required (or use --gui)")
    is_nbd = str(a.image).startswith("nbd://")
    if not is_nbd and not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "mounting_partitions", __version__)
    if not is_nbd:
        try:
            ctx.limits.check_paths([str(a.image)])
        except tracelib.LimitExceeded as e:
            print(f"resource limit: {e}", file=sys.stderr)
            return 3
        ctx.add_input(str(a.image))

    res = analyze(str(a.image), a.fmt, sector=a.sector)
    for e in res.errors:
        ctx.error("image-error", e)
    if res.errors:
        for e in res.errors:
            print(f"error: {e}", file=sys.stderr)
        return 2

    rows = [s.row() for s in res.slices]

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="no-timezone")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="no-timezone")
    if not a.quiet and not (a.csv or a.json):
        print(f"image:   {a.image}  [{res.image_format}, "
              f"{_hsize(res.image_size)}]")
        print(f"scheme:  {res.scheme}")
        print()
        print(f"{'#':>2}  {'scheme':<6} {'start LBA':>12} {'size':>12}  "
              f"{'type':<28} {'filesystem':<16} label")
        for s in res.slices:
            r = s.row()
            print(f"{r['index']:>2}  {r['scheme']:<6} {r['start_lba']:>12} "
                  f"{r['size']:>12}  {r['type'][:28]:<28} "
                  f"{r['filesystem']:<16} {r['label']}"
                  + ("  *boot" if r["bootable"] else "")
                  + (f"   ({r['note']})" if r["note"] else ""))
        if res.gaps:
            print("\ngaps / overlaps:")
            for start, end, size, kind in res.gaps:
                print(f"  {kind:<20} {start:>14} .. {end:<14}  {size}")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"mounting_partitions: {res.scheme} -> {len(res.slices)} "
          f"partition(s), {len(res.gaps)} gap(s)/overlap(s)", file=sys.stderr)
    return 0 if res.slices else 1


if __name__ == "__main__":
    raise SystemExit(main())
