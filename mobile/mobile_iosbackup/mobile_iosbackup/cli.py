from __future__ import annotations

import shutil
import sys
import argparse
from pathlib import Path

from mobile_iosbackup import __version__, tracelib
from mobile_iosbackup.backup import find_backups
from mobile_iosbackup.collect import COLUMNS, collect


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mobile_iosbackup",
        description="Read a modern (iOS 10+) local iTunes/Finder iOS "
                    "backup: Manifest.db's per-file inventory (domain, "
                    "real relative path, size, POSIX mode, timestamps) "
                    "joined with on-disk presence at the backup's hashed "
                    "<fileID[:2]>/<fileID> storage layout. Encrypted "
                    "backups are detected and reported, not decrypted "
                    "(v0.1 - see README). --extract-dir reconstructs the "
                    "real domain/relativePath folder tree from the "
                    "hash-named blobs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  mobile_iosbackup 00008030-001A2D3E1234567X\n"
                "  mobile_iosbackup \"MobileSync/Backup\" --domain "
                "CameraRollDomain --csv photos.csv\n"
                "  mobile_iosbackup 00008030-... --extract-dir ./extracted\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="a backup folder (containing Manifest.db), or a "
                   "parent 'Backup' folder to search recursively")
    p.add_argument("--version", action="version",
                   version=f"mobile_iosbackup {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--domain", help="substring filter on domain")
    p.add_argument("--path", help="substring filter on relative_path")
    p.add_argument("--type", choices=["file", "directory", "symlink"])
    p.add_argument("--missing-only", action="store_true",
                   help="only rows whose content is not present on disk")
    p.add_argument("--extract-dir", type=Path,
                   help="reconstruct domain/relativePath under this "
                   "directory for every matching on-disk file")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from mobile_iosbackup.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "mobile_iosbackup", __version__)
    try:
        ctx.limits.check_paths([a.target])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(a.target)

    res = collect([a.target])
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    rows = res.rows
    if a.domain:
        rows = [r for r in rows if a.domain.lower() in r["domain"].lower()]
    if a.path:
        rows = [r for r in rows
               if a.path.lower() in r["relative_path"].lower()]
    if a.type:
        rows = [r for r in rows if r["file_type"] == a.type]
    if a.missing_only:
        rows = [r for r in rows if not r["on_disk"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = " [id-mismatch]" if r["file_id_mismatch"] else ""
            miss = "" if r["on_disk"] else "  [missing]"
            print(f"{r['domain']}/{r['relative_path']}  ({r['size']} "
                 f"bytes){tag}{miss}")

    if a.extract_dir:
        roots = find_backups(a.target)
        n = 0
        for root in roots:
            for r in rows:
                if not r["on_disk"]:
                    continue
                src = root / r["file_id"][:2] / r["file_id"]
                if not src.is_file():
                    continue
                dest = a.extract_dir / r["domain"] / r["relative_path"]
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(src, dest)
                    n += 1
                except OSError:
                    continue
        print(f"mobile_iosbackup: extracted {n} file(s) to {a.extract_dir}",
             file=sys.stderr)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"mobile_iosbackup: {len(rows)} row(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
