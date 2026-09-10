from __future__ import annotations

import argparse
import sys
from pathlib import Path

from utilities_hash import __version__, tracelib
from utilities_hash.hashing import ALGOS, hash_all
from utilities_hash.verify import diff, load_manifest


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="utilities_hash",
        description="Hash a directory tree / file list / mounted image into a "
                    "manifest in one streaming pass (MD5 / SHA-1 / SHA-256 / "
                    "SHA-512 / SHA3-256 / BLAKE2b), or --verify a tree against "
                    "a prior manifest (added / removed / changed / moved).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  utilities_hash /mnt/evidence --csv manifest.csv\n"
                "  utilities_hash /export --algo sha256 --sum-out hashes.txt\n"
                "  utilities_hash /cases/img --algo md5,sha1,sha256 "
                "--metadata --json m.json\n"
                "  utilities_hash /mnt/evidence --verify manifest.csv\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="directories / files to hash")
    p.add_argument("--version", action="version",
                   version=f"utilities_hash {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--algo", default="sha256",
                   help="comma-separated: " + ",".join(ALGOS)
                   + " (default sha256)")
    p.add_argument("--file-list", type=Path, metavar="FILE",
                   help="hash the paths listed in FILE (one per line)")
    p.add_argument("--no-recurse", action="store_true")
    p.add_argument("--follow-symlinks", action="store_true")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    p.add_argument("--metadata", action="store_true",
                   help="include size + mtime columns (always in CSV/JSON)")
    p.add_argument("--verify", type=Path, metavar="MANIFEST",
                   help="diff the scan against a prior manifest instead of "
                        "writing one")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--sum-out", type=Path, metavar="FILE",
                   help="write the plain '<hash>  <path>' format")
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from utilities_hash.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("give at least one path (or --gui)")
    algos = [x.strip() for x in a.algo.split(",") if x.strip()]
    bad = [x for x in algos if x not in ALGOS]
    if bad:
        build_parser().error(f"unknown algo(s): {', '.join(bad)}")

    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "utilities_hash", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for s in strpaths:
        ctx.add_input(s)

    prog = None
    if not a.quiet:
        def prog(n):  # noqa: E306
            sys.stderr.write(f"\r  hashed {n} file(s)")
            sys.stderr.flush()

    res = hash_all(strpaths, algos, recurse=not a.no_recurse,
                   follow_symlinks=a.follow_symlinks, exclude=a.exclude,
                   file_list=str(a.file_list) if a.file_list else None,
                   progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    if a.verify:
        if not a.verify.exists():
            print(f"not found: {a.verify}", file=sys.stderr)
            return 2
        d = diff(load_manifest(str(a.verify)), res)
        _print_diff(d)
        ctx.finish()
        bad_n = len(d.added) + len(d.removed) + len(d.changed) + len(d.moved)
        print(f"utilities_hash: verify - {d.unchanged} unchanged, "
              f"{len(d.changed)} changed, {len(d.added)} added, "
              f"{len(d.removed)} removed, {len(d.moved)} moved",
              file=sys.stderr)
        return 1 if bad_n else 0

    columns = ["path", "size", "mtime"] + algos + ["error"]
    rows = [f.row(algos) for f in res.files]
    if a.csv:
        tracelib.write_csv(rows, a.csv, columns, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if a.sum_out:
        primary = algos[0]
        lines = [f"{f.digests.get(primary, '')}  {f.rel or f.path}"
                 for f in res.files if not f.error]
        a.sum_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not a.quiet and not (a.csv or a.json or a.sum_out):
        for f in res.files:
            if f.error:
                print(f"  !! {f.rel or f.path}: {f.error}")
                continue
            print(f"{f.digests.get(algos[0], '')}  {f.rel or f.path}")

    total_bytes = sum(f.size for f in res.files if not f.error)
    ctx.finish(outputs=[a.csv, a.json, a.sum_out])
    print(f"utilities_hash: {len(res.files)} file(s), "
          f"{total_bytes / (1 << 20):.1f} MiB, {res.errors} error(s), "
          f"algos: {', '.join(algos)}", file=sys.stderr)
    return 0 if res.files else 1


def _print_diff(d) -> None:
    for path, old, new, algo in d.changed:
        print(f"CHANGED  {path}\n         {algo} {old[:16]}… -> {new[:16]}…")
    for src, dst, h in d.moved:
        print(f"MOVED    {src}  ->  {dst}  ({h[:16]}…)")
    for path in d.added:
        print(f"ADDED    {path}")
    for path in d.removed:
        print(f"REMOVED  {path}")


if __name__ == "__main__":
    raise SystemExit(main())
