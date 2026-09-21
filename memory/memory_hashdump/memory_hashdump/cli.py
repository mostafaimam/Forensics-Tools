from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_hashdump import __version__, tracelib
from memory_hashdump.collect import COLUMNS, dump


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_hashdump",
        description="Extract local NT/LM password hashes given a SYSTEM + "
                    "SAM hive pair: derives the SYSTEM hive's boot key "
                    "(no examiner-supplied secret needed - it's recoverable "
                    "from the hive alone, by Windows' own design) and uses "
                    "it to decrypt each account's stored hash. Reporting "
                    "only - hashes are not cracked into passwords here.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  memory_hashdump --system SYSTEM --sam SAM\n"
                "  memory_hashdump --system SYSTEM --sam SAM --csv "
                "hashes.csv\n"))
    p.add_argument("--system", required=True, type=Path,
                   help="path to the SYSTEM hive file")
    p.add_argument("--sam", required=True, type=Path,
                   help="path to the SAM hive file")
    p.add_argument("--version", action="version",
                   version=f"memory_hashdump {__version__}")
    p.add_argument("--empty-only", action="store_true",
                   help="only accounts with a blank NT hash")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    for label, path in (("--system", a.system), ("--sam", a.sam)):
        if not path.exists():
            print(f"not found: {label} {path}", file=sys.stderr)
            return 2

    ctx = tracelib.context(a, "memory_hashdump", __version__)
    ctx.add_input(str(a.system))
    ctx.add_input(str(a.sam))

    res = dump(str(a.system), str(a.sam))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not res.rows and res.warnings:
        return 1

    rows = res.rows
    if a.empty_only:
        rows = [r for r in rows if r["nt_empty"]]

    if not a.quiet and not (a.csv or a.json):
        scheme = {2: "legacy RC4", 3: "modern AES"}.get(res.revision, "?")
        print(f"SAM scheme: {scheme} (F revision {res.revision})",
             file=sys.stderr)
        for r in rows:
            flag = "  [blank NT hash]" if r["nt_empty"] else ""
            print(f"{r['rid']:<6} {r['username']:<20} "
                 f"{r['lm_hash'] or '-':<32} {r['nt_hash'] or '-'}{flag}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_hashdump: {len(rows)} account(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
