from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analysis_gallery import __version__, tracelib
from analysis_gallery.output import (COLUMNS, render_table, row, write_csv,
                                     write_json)
from analysis_gallery.report import write_html
from analysis_gallery.scan import scan


def _csv_set(s: str) -> set[str]:
    return {x.strip() for x in s.split(",") if x.strip()}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_gallery",
        description="Find every image and video in an evidence set, extract "
                    "EXIF / QuickTime metadata and GPS, group visually "
                    "near-identical pictures, and build a contact sheet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_gallery scan /cases/evidence --html gallery.html\n"
            "  analysis_gallery scan /mnt/image --phash --csv pics.csv\n"
            "  analysis_gallery scan /dcim --gps-only --json geo.json\n"
            "  analysis_gallery scan /export --category image --phash "
            "--threshold 6\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"analysis_gallery {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan paths for media")
    s.add_argument("paths", nargs="+", type=Path)
    s.add_argument("--phash", action="store_true",
                   help="compute a perceptual hash and group look-alikes")
    s.add_argument("--threshold", type=int, default=10, metavar="N",
                   help="max dHash Hamming distance for a group (default 10)")
    s.add_argument("--category", type=_csv_set, metavar="C,C",
                   help="keep only image / video")
    s.add_argument("--gps-only", action="store_true",
                   help="keep only geotagged files")
    s.add_argument("--no-exif-only", action="store_true",
                   help="keep only files with no EXIF (stripped / re-saved)")
    s.add_argument("--include", action="append", default=[], metavar="GLOB")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    s.add_argument("--min-size", type=int, default=0, metavar="BYTES")
    s.add_argument("--no-hash", action="store_true",
                   help="skip SHA-256 (faster)")
    s.add_argument("--follow-symlinks", action="store_true")
    s.add_argument("--csv", type=Path)
    s.add_argument("--json", type=Path)
    s.add_argument("--html", type=Path, metavar="FILE",
                   help="write a self-contained HTML contact sheet")
    s.add_argument("--thumb-box", type=int, default=220, metavar="PX")
    s.add_argument("--max-decode-mp", type=float, default=None, metavar="MP",
                   help="decode images up to this many megapixels for hashing "
                        "/ thumbnails (default ~1.5 MP PNG, ~3 MP JPEG - the "
                        "in-tree decoders are slow on big images; raise it for "
                        "a targeted photo set)")
    s.add_argument("-q", "--quiet", action="store_true")

    gp = sub.add_parser("gui", help="open the graphical viewer")
    gp.add_argument("paths", nargs="*", type=Path)
    tracelib.add_arguments(p)
    return p


def _cmd_scan(a) -> int:
    ctx = tracelib.context(a, "analysis_gallery", __version__)
    try:
        ctx.limits.check_paths([str(p) for p in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for _p in a.paths:
        ctx.add_input(str(_p))
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    prog = None
    if not a.quiet:
        def prog(n):  # noqa: E306
            sys.stderr.write(f"\r  {n} media files…")
            sys.stderr.flush()

    want_thumbs = a.html is not None
    res = scan([str(p) for p in a.paths],
               phash_on=a.phash,
               threshold=a.threshold, want_thumbs=want_thumbs,
               hash_files=not a.no_hash, include=a.include, exclude=a.exclude,
               min_size=a.min_size, categories=a.category,
               follow_symlinks=a.follow_symlinks,
               max_decode_mp=a.max_decode_mp, progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    files = res.files
    if a.gps_only:
        files = [f for f in files if f.has_gps]
    if a.no_exif_only:
        files = [f for f in files if not f.has_exif and f.category == "image"]

    rows = [row(f) for f in files]
    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if a.html:
        write_html(files, a.html, thumb_box=a.thumb_box)
    if not a.quiet and not (a.csv or a.json or a.html):
        print(render_table(rows), end="")

    grp = len({f.phash_group for f in files if f.phash_group})
    msg = (f"analysis_gallery: {len(files)} media "
           f"({sum(1 for f in files if f.category == 'image')} img, "
           f"{sum(1 for f in files if f.category == 'video')} vid), "
           f"{sum(1 for f in files if f.has_gps)} geotagged, "
           f"{sum(1 for f in files if f.has_exif)} with metadata")
    if a.phash:
        msg += f", {grp} look-alike group(s)"
    if res.skipped:
        msg += f"; {res.skipped} non-media skipped"
    if res.errors:
        msg += f"; {res.errors} error(s)"
    print(msg, file=sys.stderr)
    ctx.finish(outputs=[a.csv, a.json, getattr(a, 'html', None)])

    return 0 if files else 1


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.cmd:
        build_parser().print_help()
        return 2
    if a.cmd == "gui":
        from analysis_gallery.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    return _cmd_scan(a)


if __name__ == "__main__":
    raise SystemExit(main())
