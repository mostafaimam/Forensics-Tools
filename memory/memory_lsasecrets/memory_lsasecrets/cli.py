from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_lsasecrets import __version__, tracelib
from memory_lsasecrets.collect import COLUMNS, dump


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_lsasecrets",
        description="Decrypt LSA secrets given a SYSTEM + SECURITY hive "
                    "pair: service-account passwords (_SC_*), the DPAPI "
                    "machine key, auto-logon passwords, and other "
                    "SECURITY\\Policy\\Secrets entries. No examiner "
                    "-supplied secret needed - the LSA key is recoverable "
                    "from the two hives alone, by Windows' own design. "
                    "Reporting only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  memory_lsasecrets --system SYSTEM --security SECURITY\n"
                "  memory_lsasecrets --system SYSTEM --security SECURITY "
                "--csv secrets.csv\n"))
    p.add_argument("--system", required=True, type=Path,
                   help="path to the SYSTEM hive file")
    p.add_argument("--security", required=True, type=Path,
                   help="path to the SECURITY hive file")
    p.add_argument("--version", action="version",
                   version=f"memory_lsasecrets {__version__}")
    p.add_argument("--reversible-only", action="store_true",
                   help="only secrets with a plaintext-reversible name "
                   "(_SC_* service-account passwords)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    for label, path in (("--system", a.system), ("--security", a.security)):
        if not path.exists():
            print(f"not found: {label} {path}", file=sys.stderr)
            return 2

    ctx = tracelib.context(a, "memory_lsasecrets", __version__)
    ctx.add_input(str(a.system))
    ctx.add_input(str(a.security))

    res = dump(str(a.system), str(a.security))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not res.rows and res.warnings:
        return 1

    rows = res.rows
    if a.reversible_only:
        rows = [r for r in rows if r["reversible"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = f"  [{r['notable']}]" if r["notable"] else ""
            shown = r["value_text"] or f"(binary, {len(r['value_hex']) // 2} "\
                f"bytes)"
            print(f"{r['name']:<24} {shown}{tag}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_lsasecrets: {len(rows)} secret(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
