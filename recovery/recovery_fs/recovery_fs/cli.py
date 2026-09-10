from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

from recovery_fs import __version__, tracelib
from recovery_fs.open import FsError, open_fs

COLUMNS = ["path", "name", "type", "size", "allocated", "inode", "created",
           "modified", "accessed", "changed", "fs"]


def _num(s):
    return int(str(s), 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recovery_fs",
        description="One read-only file-system walker. Detects NTFS / FAT / "
                    "exFAT (ext / HFS+ / APFS detected only) at --offset or "
                    "the first partition, then: list (allocated + deleted), "
                    "extract by path or inode, cat a file, or emit a "
                    "bodyfile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  recovery_fs list disk.raw --deleted-only --csv files.csv\n"
                "  recovery_fs list usb.img --glob '*.jpg'\n"
                "  recovery_fs extract disk.raw --glob 'Users/*/Documents/*' "
                "-o ./out\n"
                "  recovery_fs cat part.img --path 'Windows/System32/"
                "drivers/etc/hosts'\n"
                "  recovery_fs bodyfile disk.raw -o fs.body\n"))
    s = p.add_subparsers(dest="cmd")
    p.add_argument("--version", action="version",
                   version=f"recovery_fs {__version__}")

    for name in ("list", "extract", "cat", "bodyfile"):
        sp = s.add_parser(name)
        sp.add_argument("image", type=Path)
        sp.add_argument("--offset", type=_num, default=None,
                        help="byte offset of the volume (default: auto)")
        sp.add_argument("--deleted-only", action="store_true")
        sp.add_argument("--files-only", action="store_true")
        sp.add_argument("--glob", metavar="PATTERN",
                        help="match the full path (fnmatch)")
        sp.add_argument("--path", metavar="PATH", help="exact path")
        sp.add_argument("--inode", type=int)
        if name == "list":
            sp.add_argument("--csv", type=Path)
            sp.add_argument("--json", type=Path)
            sp.add_argument("--limit", type=int, default=0)
        if name in ("extract", "bodyfile", "cat"):
            sp.add_argument("-o", "--out", type=Path,
                            required=(name in ("extract", "bodyfile")))
        sp.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _select(be, a):
    for e in be.entries(include_deleted=not a.files_only or True):
        if a.deleted_only and e.allocated:
            continue
        if a.files_only and e.is_dir:
            continue
        if a.path and e.path != a.path.replace("\\", "/"):
            continue
        if a.inode is not None and e.inode != a.inode:
            continue
        if a.glob and not fnmatch.fnmatch(e.path, a.glob):
            continue
        yield e


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd not in ("list", "extract", "cat", "bodyfile"):
        build_parser().print_help()
        return 2
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "recovery_fs", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))

    try:
        be, off, fs = open_fs(str(a.image), offset=a.offset)
    except FsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not a.quiet:
        print(f"file system: {fs}  (volume offset {off:#x})",
              file=sys.stderr)

    rc = 0
    if a.cmd == "list":
        rows = []
        for e in _select(be, a):
            rows.append(e.row())
            if a.limit and len(rows) >= a.limit:
                break
        if a.csv:
            tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                               confidence="high", tz="utc-native")
        if a.json:
            tracelib.write_json(rows, a.json, ctx,
                                confidence="high", tz="utc-native")
        if not a.quiet and not (a.csv or a.json):
            for r in rows:
                flag = " " if r["allocated"] == "yes" else "*"
                print(f"{flag} {r['type'][0]} {r['size']:>12}  "
                      f"{r['modified'] or '':<20}  {r['path']}")
        deleted = sum(1 for r in rows if r["allocated"] != "yes")
        print(f"recovery_fs: {len(rows)} entr(y/ies), {deleted} deleted",
              file=sys.stderr)
        rc = 0 if rows else 1

    elif a.cmd == "cat":
        got = next(_select(be, a), None)
        if got is None:
            print("no matching file", file=sys.stderr)
            rc = 1
        else:
            data = be.read(got)
            if a.out:
                a.out.write_bytes(data)
            else:
                sys.stdout.buffer.write(data)

    elif a.cmd == "extract":
        a.out.mkdir(parents=True, exist_ok=True)
        n = 0
        for e in _select(be, a):
            if e.is_dir:
                continue
            safe = e.path.replace("..", "__").lstrip("/")
            dest = a.out / safe
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                dest.write_bytes(be.read(e))
                n += 1
            except Exception as exc:  # noqa: BLE001
                ctx.error("extract-error", f"{e.path}: {exc}")
        print(f"recovery_fs: extracted {n} file(s) to {a.out}",
              file=sys.stderr)
        rc = 0 if n else 1

    elif a.cmd == "bodyfile":
        lines = [e.bodyfile() for e in _select(be, a)]
        a.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"recovery_fs: wrote {len(lines)} bodyfile line(s) to {a.out}",
              file=sys.stderr)
        rc = 0 if lines else 1

    be.close()
    ctx.finish(outputs=[getattr(a, "csv", None), getattr(a, "json", None),
                        getattr(a, "out", None)])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
