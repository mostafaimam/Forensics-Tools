from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_thumbcache import __version__, tracelib
from windows_thumbcache.analyze import analyze
from windows_thumbcache import thumbcache as _tc

COLUMNS = ["cache_id", "identifier", "format", "width", "height", "data_size",
           "db", "last_modified", "idx_flags", "severity", "notable"]

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
_FSEV = {
    "identifier points at a user-writable path": "medium",
    "identifier points at a removable / network path": "medium",
    "thumbnail data is not a recognised image format": "low",
    "unusually large thumbnail": "low",
}


def _severity(notable) -> str:
    top = "none"
    for n in notable:
        for k, v in _FSEV.items():
            if n.startswith(k) and _SEV[v] > _SEV[top]:
                top = v
    return top


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_thumbcache",
        description="Parse thumbcache_*.db (and thumbcache_idx.db) from the "
                    "Explorer thumbnail cache. One row per cached thumbnail: "
                    "cache id, identifier (path or hex id), image format, "
                    "dimensions, data size, which .db it came from and - "
                    "from the index - the source file's last-modified time "
                    "(FILETIME, UTC). --extract writes every thumbnail out "
                    "as an image file: evidence of pictures that may no "
                    "longer be on disk. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_thumbcache thumbcache_256.db --csv thumbs.csv\n"
                "  windows_thumbcache E:\\ --extract ./thumbs\n"
                "  windows_thumbcache C:\\...\\Explorer --notable-only\n"))
    p.add_argument("path", type=Path,
                   help="a thumbcache_*.db, the Explorer folder, or a root")
    p.add_argument("--version", action="version",
                   version=f"windows_thumbcache {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--extract", type=Path, metavar="DIR",
                   help="write every thumbnail image into this directory")
    p.add_argument("--format", dest="fmt", help="only this image format")
    p.add_argument("--grep", metavar="REGEX", help="match the identifier")
    p.add_argument("--min-size", type=int, default=0)
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from windows_thumbcache.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_thumbcache", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = analyze([str(a.path)])
    for d in res.dbs:
        ctx.add_input(d)
    for e in res.errors:
        ctx.error("thumbcache-error", e)
    if not res.index_entries:
        ctx.partial("no-index", "no thumbcache_idx.db - the source-file "
                    "last-modified times are unavailable")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    keep = []
    for t in res.thumbnails:
        r = t.row()
        r["severity"] = _severity(t.notable)
        if a.fmt and r["format"] != a.fmt:
            continue
        if a.min_size and t.data_size < a.min_size:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r["identifier"]):
            continue
        rows.append(r)
        keep.append(t)

    extracted = 0
    if a.extract:
        a.extract.mkdir(parents=True, exist_ok=True)
        blobs = _load_blobs(a.path, res)
        for t in keep:
            blob = blobs.get((t.db_name, t.data_offset))
            if not blob:
                continue
            ext = t.fmt or "bin"
            (a.extract / f"{t.cache_id:016x}.{ext}").write_bytes(blob)
            extracted += 1

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            dims = f"{r['width']}x{r['height']}" if r["width"] else ""
            out = f"{r['cache_id']}  {r['format'] or '?':<5} {dims:<9} " \
                  f"{r['data_size']:>8}  {r['identifier'][:60]}{mark}"
            print(out)
            if r["notable"]:
                print("    ! " + ", ".join(r["notable"].split(";")))

    ctx.finish(outputs=[a.csv, a.json])
    print(f"windows_thumbcache: {len(res.thumbnails)} thumbnail(s) from "
          f"{len(res.dbs)} db(s) [{', '.join(sorted(res.versions))}] -> "
          f"{len(rows)} shown"
          + (f", {extracted} extracted" if a.extract else ""),
          file=sys.stderr)
    return 0 if rows else 1


def _load_blobs(path: Path, res) -> dict:
    """Re-read each .db and slice out the image bytes by offset."""
    out: dict = {}
    for d in res.dbs:
        p = Path(d)
        try:
            data = p.read_bytes()
        except OSError:
            continue
        cf = _tc.parse_cache(data, p.name)
        for t in cf.entries:
            out[(p.name, t.data_offset)] = data[t.data_offset:
                                                t.data_offset + t.data_size]
    return out


if __name__ == "__main__":
    raise SystemExit(main())
