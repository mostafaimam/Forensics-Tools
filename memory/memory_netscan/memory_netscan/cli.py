from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_netscan import __version__
from memory_netscan.loader import MemoryImage, MemoryImageError
from memory_netscan.netscan import scan
from memory_netscan.output import COLUMNS, render, row, write_csv, write_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_netscan",
        description="Recover network connections and listening sockets from a "
                    "Windows RAM dump by pool-tag scanning (finds hidden and "
                    "already-closed connections; profile-independent, so "
                    "expect some false positives and partial rows).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_netscan MEMORY.DMP\n"
            "  memory_netscan mem.lime --listeners --csv sockets.csv\n"
            "  memory_netscan mem.raw --proto tcp --established\n"
            "  memory_netscan MEMORY.DMP --process chrome --json net.json\n"
        ),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_netscan {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--proto", choices=["tcp", "udp"],
                   help="keep only this protocol")
    p.add_argument("--listeners", action="store_true",
                   help="keep only listening sockets")
    p.add_argument("--established", action="store_true",
                   help="keep only ESTABLISHED TCP endpoints")
    p.add_argument("--process", metavar="SUBSTR",
                   help="keep rows whose owning process matches this substring")
    p.add_argument("--port", type=int, action="append", default=[],
                   metavar="N", help="keep rows using this local or remote port")
    p.add_argument("--min-confidence", choices=["low", "medium", "high"],
                   default="low")
    p.add_argument("--no-translation", action="store_true",
                   help="skip address-space translation (faster, fewer fields)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_netscan.gui import run_gui
        return run_gui([str(a.image)] if a.image else [])
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    try:
        img = MemoryImage(a.image)
    except MemoryImageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    prog = None
    if not a.quiet:
        def prog(done, total):  # noqa: E306
            pct = f"{100 * done // total}%" if total else f"{done}"
            sys.stderr.write(f"\r  scanning {pct}")
            sys.stderr.flush()

    eps = scan(img, use_translation=not a.no_translation, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    order = {"low": 0, "medium": 1, "high": 2}
    rows = []
    for e in eps:
        if a.proto and e.proto.lower() != a.proto:
            continue
        if a.listeners and e.role != "listener":
            continue
        if a.established and e.state != "ESTABLISHED":
            continue
        if a.process and a.process.lower() not in e.process.lower():
            continue
        if a.port and e.local_port not in a.port and e.remote_port not in a.port:
            continue
        if order[e.confidence] < order[a.min_confidence]:
            continue
        rows.append(row(e))

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    tcp = sum(1 for r in rows if r["proto"] == "TCP")
    udp = len(rows) - tcp
    named = sum(1 for r in rows if r["process"])
    print(f"memory_netscan: {len(rows)} endpoint(s) - {tcp} TCP, {udp} UDP, "
          f"{named} with an owning process", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
