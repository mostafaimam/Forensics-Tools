from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from recovery_carve import __version__
from recovery_carve.output import Writer
from recovery_carve.scanner import ScanOptions, Source, scan
from recovery_carve.signatures import all_signatures, select

_HASHES = ("md5", "sha1", "sha256")


def _size(text: str) -> int:
    text = text.strip().lower()
    mult = 1
    for suf, m in (("kb", 1024), ("mb", 1024**2), ("gb", 1024**3),
                   ("k", 1024), ("m", 1024**2), ("g", 1024**3), ("b", 1)):
        if text.endswith(suf):
            mult = m
            text = text[:-len(suf)]
            break
    return int(float(text) * mult)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recovery_carve",
        description="Recover files from a raw image, device or unallocated "
                    "blob by magic-byte signature carving with structural "
                    "validators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  recovery_carve disk.dd -o carved/\n"
            "  recovery_carve unalloc.bin -o out/ --types jpg,png,pdf --hash md5,sha1\n"
            "  recovery_carve image.raw -o out/ --category image,document --manifest-only\n"
        ),
    )
    p.add_argument("source", nargs="?", metavar="IMAGE",
                   help="raw image / device / file to carve")
    p.add_argument("-o", "--out", metavar="DIR", type=Path,
                   help="output directory")
    p.add_argument("--version", action="version",
                   version=f"recovery_carve {__version__}")
    p.add_argument("--list-signatures", action="store_true")

    sel = p.add_argument_group("selection")
    sel.add_argument("--types", type=lambda s: s.split(","), default=None,
                     metavar="ID,ID")
    sel.add_argument("--category", type=lambda s: s.split(","), default=None,
                     metavar="C,C")

    tune = p.add_argument_group("tuning")
    tune.add_argument("--min-size", type=_size, default="8", metavar="SIZE")
    tune.add_argument("--max-size", type=_size, default=None, metavar="SIZE",
                      help="global cap overriding each signature's own limit")
    tune.add_argument("--hash", dest="hashes", type=lambda s: s.split(","),
                      default=["sha1"], metavar=",".join(_HASHES))
    tune.add_argument("--nested", action="store_true",
                      help="also carve objects found inside other carved objects")
    tune.add_argument("--max-per-type", type=int, default=None, metavar="N")
    tune.add_argument("--manifest-only", action="store_true",
                      help="do not write recovered files, only the manifest")
    tune.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_signatures:
        for s in all_signatures():
            v = " [validated]" if s.validator else ""
            print(f"  {s.id:<8} {s.category:<11} .{s.ext:<6} {s.description}{v}")
        return 0

    if not args.source or not args.out:
        print("error: IMAGE and -o/--out are required", file=sys.stderr)
        return 2

    src_path = Path(args.source)
    if not src_path.exists():
        print(f"error: source not found: {src_path}", file=sys.stderr)
        return 2

    bad = [h for h in args.hashes if h.lower() not in _HASHES]
    if bad:
        print(f"error: unsupported hash(es): {bad}", file=sys.stderr)
        return 2

    try:
        sigs = select(args.types, args.category)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.max_size:
        sigs = [type(s)(**{**s.__dict__, "max_size": min(s.max_size, args.max_size)})
                for s in sigs]

    opts = ScanOptions(
        min_size=args.min_size,
        hashes=tuple(h.lower() for h in args.hashes),
        nested=args.nested,
        max_hits_per_sig=args.max_per_type,
    )

    last = [0.0]

    def progress(done: int, total: int) -> None:
        if args.quiet:
            return
        now = time.time()
        if now - last[0] < 0.5 and done < total:
            return
        last[0] = now
        pct = 100.0 * done / total if total else 100.0
        print(f"\r  scanning {pct:5.1f}%  ({done:,} / {total:,} bytes)",
              end="", file=sys.stderr, flush=True)

    with Source(str(src_path)) as src:
        writer = Writer(args.out, src, write_files=not args.manifest_only)
        try:
            for carving in scan(src, sigs, opts, progress):
                writer.add(carving)
        finally:
            writer.close()

    if not args.quiet:
        print(file=sys.stderr)
    print(f"recovery_carve {__version__}: {writer.count} object(s), "
          f"{writer.bytes:,} bytes carved from {src.size:,}-byte source",
          file=sys.stderr)
    print(f"  manifest: {args.out / 'recovery_carve_manifest.csv'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
