from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from memory_image import __version__
from memory_image.convert import carve, convert
from memory_image.loader import MemoryImage, MemoryImageError


def _int(s: str) -> int:
    return int(s, 0)


def _si(n) -> str:
    f = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or u == "TiB":
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_image",
        description="Identify, map and convert RAM dumps (raw / LiME / ELF "
                    "core / Windows crash dump).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_image info mem.lime\n"
            "  memory_image ranges MEMORY.DMP --json ranges.json\n"
            "  memory_image convert mem.lime mem.raw --format raw\n"
            "  memory_image carve mem.lime --physical 0x1000 --size 4096 --out page.bin\n"
            "  memory_image read mem.raw --physical 0x0 --size 64\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"memory_image {__version__}")
    sub = p.add_subparsers(dest="cmd")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("image", type=Path)

    i = sub.add_parser("info", parents=[common], help="format + map + OS hints")
    i.add_argument("--json", type=Path)
    i.add_argument("--no-scan", action="store_true",
                   help="skip the Linux/Windows banner scan")

    r = sub.add_parser("ranges", parents=[common], help="physical range map")
    r.add_argument("--json", type=Path)

    c = sub.add_parser("convert", parents=[common], help="transcode the layout")
    c.add_argument("out", type=Path)
    c.add_argument("--format", choices=["raw", "lime", "padded"], required=True)
    c.add_argument("-q", "--quiet", action="store_true")

    cv = sub.add_parser("carve", parents=[common],
                        help="extract a physical region to a raw file")
    cv.add_argument("--physical", type=_int, required=True)
    cv.add_argument("--size", type=_int, required=True)
    cv.add_argument("--out", type=Path, required=True)

    rd = sub.add_parser("read", parents=[common],
                        help="hexdump a physical range to stdout")
    rd.add_argument("--physical", type=_int, required=True)
    rd.add_argument("--size", type=_int, default=256)
    rd.add_argument("--raw", action="store_true", help="bytes, not a hexdump")
    return p


def _hexdump(data: bytes, base: int) -> str:
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{base + i:#014x}  {hexs}  {asc}")
    return "\n".join(out)


def _cmd_info(a) -> int:
    with MemoryImage(a.image) as img:
        if not a.no_scan:
            img.scan_os_hints()
        info = img.info()
    if a.json:
        a.json.write_text(json.dumps(info.__dict__, indent=2, default=str))
    print(f"file          : {a.image}")
    print(f"format        : {info.fmt}")
    print(f"file size     : {info.file_size} ({_si(info.file_size)})")
    print(f"physical size : {info.phys_size} ({_si(info.phys_size)})")
    print(f"mapped        : {info.mapped_size} ({_si(info.mapped_size)}) "
          f"in {len(info.runs)} run(s)")
    for k, v in info.os_hints.items():
        vv = f"{v:#x}" if isinstance(v, int) and v > 0xffff else v
        print(f"  {k:<24}: {vv}")
    for w in info.warnings:
        print(f"  ! {w}", file=sys.stderr)
    return 0


def _cmd_ranges(a) -> int:
    with MemoryImage(a.image) as img:
        runs = img.info().runs
    if a.json:
        a.json.write_text(json.dumps(runs, indent=2))
    else:
        print(f"  {'phys start':>16}  {'phys end':>16}  {'size':>14}  "
              f"{'file offset':>14}")
        for r in runs:
            print(f"  {r['phys_start']:#016x}  "
                  f"{r['phys_start'] + r['size']:#016x}  "
                  f"{_si(r['size']):>14}  {r['file_offset']:#014x}")
    return 0 if runs else 1


def _prog(quiet):
    if quiet:
        return None
    return lambda done, total: (sys.stderr.write(
        f"\r  {done}/{total} bytes "
        f"({done / total * 100:4.1f}%)" if total else f"\r  {done} bytes")
        or sys.stderr.flush())


def _cmd_convert(a) -> int:
    with MemoryImage(a.image) as img:
        n = convert(img, str(a.out), a.format, progress=_prog(a.quiet))
    if not a.quiet:
        sys.stderr.write("\n")
    print(f"wrote {n} bytes -> {a.out}", file=sys.stderr)
    return 0


def _cmd_carve(a) -> int:
    with MemoryImage(a.image) as img:
        n = carve(img, str(a.out), a.physical, a.size)
    print(f"wrote {n} bytes ({a.physical:#x}..{a.physical + a.size:#x}) "
          f"-> {a.out}", file=sys.stderr)
    return 0


def _cmd_read(a) -> int:
    with MemoryImage(a.image) as img:
        data = img.read_physical(a.physical, a.size)
    if a.raw:
        sys.stdout.buffer.write(data)
    else:
        print(_hexdump(data, a.physical))
    return 0


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.cmd:
        build_parser().print_help()
        return 2
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    try:
        return {"info": _cmd_info, "ranges": _cmd_ranges,
                "convert": _cmd_convert, "carve": _cmd_carve,
                "read": _cmd_read}[a.cmd](a)
    except MemoryImageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
