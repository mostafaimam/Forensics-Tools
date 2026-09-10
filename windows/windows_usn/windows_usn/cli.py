from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

from windows_usn import __version__, tracelib
from windows_usn import usnparse as _u
from windows_usn.analyze import analyze, severity

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}

COLUMNS = ["ts", "op", "name", "old_name", "path", "file_entry",
           "file_sequence", "parent_entry", "usn_first", "usn_last",
           "reasons", "attributes", "carved", "severity", "source", "notable"]


def _mft_paths(mft_path: Path) -> dict[int, str]:
    """Very small $MFT reader: entry -> name, then join to a path.

    Only needs the $FILE_NAME of each record; enough to resolve parents.
    """
    try:
        data = mft_path.read_bytes()
    except OSError:
        return {}
    names: dict[int, tuple[str, int]] = {}
    rec_size = 1024
    if data[:4] == b"FILE" and len(data) > 0x1E:
        a = struct.unpack_from("<H", data, 0x1E)[0]
        if a:
            rec_size = a if a >= 256 else 1 << a
    for i in range(len(data) // rec_size):
        r = data[i * rec_size:(i + 1) * rec_size]
        if r[:4] not in (b"FILE", b"BAAD"):
            continue
        try:
            first_attr = struct.unpack_from("<H", r, 0x14)[0]
        except struct.error:
            continue
        off = first_attr
        while off + 8 < len(r):
            atype = struct.unpack_from("<I", r, off)[0]
            if atype == 0xFFFFFFFF:
                break
            alen = struct.unpack_from("<I", r, off + 4)[0]
            if alen == 0:
                break
            if atype == 0x30:                     # $FILE_NAME
                coff = struct.unpack_from("<H", r, off + 0x14)[0]
                p = off + coff
                parent = struct.unpack_from("<Q", r, p)[0] & 0xFFFFFFFFFFFF
                nlen = r[p + 0x40]
                nm = r[p + 0x42:p + 0x42 + nlen * 2].decode("utf-16-le",
                                                            "replace")
                names[i] = (nm, parent)
            off += alen
    paths: dict[int, str] = {}

    def resolve(entry: int, depth=0) -> str:
        if entry in paths:
            return paths[entry]
        if depth > 64 or entry not in names:
            return ""
        nm, parent = names[entry]
        if entry == 5 or parent == entry:
            paths[entry] = nm if nm != "." else ""
            return paths[entry]
        pp = resolve(parent, depth + 1)
        paths[entry] = f"{pp}\\{nm}" if pp else nm
        return paths[entry]

    for e in list(names):
        resolve(e)
    return paths


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_usn",
        description="Standalone NTFS change-journal ($UsnJrnl:$J) parser and "
                    "carver. Walks an extracted $J stream in order, or "
                    "carves USN_RECORD (v2 / v3) structures out of a raw "
                    "image / unallocated space to recover records no longer "
                    "in the live journal. Folds consecutive records for a "
                    "file into one operation (create / rename / delete / "
                    "data-write / attr). With --mft the parent reference is "
                    "resolved to a path. Flags executables created in a "
                    "writable path, create-then-delete, mass-delete bursts "
                    "and attribute-only changes. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_usn J_stream.bin --csv usn.csv\n"
                "  windows_usn '$UsnJrnl_$J' --mft '$MFT' --json usn.json\n"
                "  windows_usn unalloc.bin --carve --notable-only\n"
                "  windows_usn J.bin --op delete --grep '\\.docx$'\n"))
    p.add_argument("path", type=Path, help="the $J stream / image / blob")
    p.add_argument("--version", action="version",
                   version=f"windows_usn {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--carve", action="store_true",
                   help="scan every 8-byte boundary for USN records "
                        "(for unallocated space / slack)")
    p.add_argument("--also-carve", action="store_true",
                   help="sequential walk PLUS a carve pass, merged")
    p.add_argument("--mft", type=Path, help="an $MFT to resolve paths")
    p.add_argument("--op", help="only this operation")
    p.add_argument("--grep", metavar="REGEX", help="match name / path")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
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
        from windows_usn.gui import run_gui
        return run_gui([str(a.path)] + ([str(a.mft)] if a.mft else []))
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_usn", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.path))

    data = a.path.read_bytes()
    if a.carve:
        records = list(_u.iter_carved(data))
    elif a.also_carve:
        seen = set()
        records = []
        for r in list(_u.iter_sequential(data)) + list(_u.iter_carved(data)):
            key = (r.usn, r.file_entry, r.reason, r.name)
            if key not in seen:
                seen.add(key)
                records.append(r)
    else:
        records = list(_u.iter_sequential(data))

    paths = {}
    if a.mft and a.mft.exists():
        ctx.add_input(str(a.mft))
        paths = _mft_paths(a.mft)

    res = analyze(records, paths)
    if res.records == 0:
        ctx.partial("no-records", "no USN records found (try --carve)")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for o in res.operations:
        r = o.row()
        r["severity"] = severity(o.notable)
        if a.op and r["op"] != a.op:
            continue
        if a.since and (not r["ts"] or r["ts"][:10] < a.since):
            continue
        if a.until and (not r["ts"] or r["ts"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(f"{r['name']} {r['old_name']} {r['path']}"):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f" [{r['severity']}]" if r["severity"] != "none" else ""
            print(f"{r['ts'] or '(no time)':<28} {r['op']:<10} "
                  f"{r['path'] or r['name']}{mark}")
            if r["notable"]:
                print("    ! " + ", ".join(r["notable"].split(";")))

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_usn: {res.records} record(s) ({res.carved} carved) -> "
          f"{len(res.operations)} operation(s) -> {len(rows)} shown, "
          f"{fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
