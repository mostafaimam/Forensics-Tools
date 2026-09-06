from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import json
import sys
from pathlib import Path

from analysis_encryption import __version__
from analysis_encryption.detect import CLEAR, analyse

_COLUMNS = ["path", "size", "verdict", "scheme", "detail", "entropy", "evidence"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _iter(paths, recurse, follow, exclude):
    for raw in paths:
        p = Path(raw)
        cands = [p] if p.is_file() else (
            p.rglob("*") if recurse else p.glob("*")) if p.is_dir() else []
        for f in cands:
            try:
                if not f.is_file() or (not follow and f.is_symlink()):
                    continue
            except OSError:
                continue
            s = str(f)
            if any(fnmatch.fnmatch(s, g) or fnmatch.fnmatch(f.name, g)
                   for g in exclude):
                continue
            yield f


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_encryption",
        description="Detect encrypted / password-protected files and "
                    "containers - Office, PDF, ZIP, RAR, 7-Zip, PGP, age, "
                    "OpenSSL, BitLocker, LUKS, FileVault DMG, KeePass, "
                    "SQLCipher, plus an entropy fallback for headerless "
                    "containers.  REPORT ONLY - nothing is decrypted or "
                    "cracked.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_encryption scan /mnt/evidence --csv encrypted.csv\n"
            "  analysis_encryption scan /cases --include-clear --json all.json\n"
            "  analysis_encryption scan secret.tc\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"analysis_encryption {__version__}")
    s = p.add_subparsers(dest="cmd")
    sc = s.add_parser("scan", help="scan files")
    sc.add_argument("paths", nargs="+", type=Path)
    sc.add_argument("--min-entropy", type=float, default=7.90,
                    help="entropy threshold for the headerless fallback")
    sc.add_argument("--include-clear", action="store_true",
                    help="also list files with no indication of encryption")
    sc.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    sc.add_argument("--no-recurse", action="store_true")
    sc.add_argument("--follow-symlinks", action="store_true")
    sc.add_argument("--csv", type=Path)
    sc.add_argument("--json", type=Path)
    sc.add_argument("-q", "--quiet", action="store_true")
    return p


def _render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        out.write(f"  {r['verdict']:<19} {r['scheme'] or '-':<16} "
                  f"ent={r['entropy']:<6} {r['path']}\n")
        if r["detail"]:
            out.write(f"      {r['detail']}\n")
    return out.getvalue()


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd != "scan":
        build_parser().print_help()
        return 2
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    rows = []
    n = 0
    for f in _iter([str(x) for x in a.paths], not a.no_recurse,
                   a.follow_symlinks, a.exclude):
        fnd = analyse(str(f), min_entropy=a.min_entropy)
        n += 1
        if not a.quiet and n % 100 == 0:
            sys.stderr.write(f"\r  scanned {n}")
            sys.stderr.flush()
        if fnd.verdict == CLEAR and not a.include_clear:
            continue
        rows.append({"path": fnd.path, "size": fnd.size, "verdict": fnd.verdict,
                     "scheme": fnd.scheme, "detail": fnd.detail,
                     "entropy": fnd.entropy, "evidence": fnd.evidence})
    if not a.quiet:
        sys.stderr.write("\r" + " " * 20 + "\r")

    if a.csv:
        with a.csv.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=_COLUMNS, dialect="excel")
            w.writeheader()
            for r in rows:
                w.writerow({k: _san(r.get(k, "")) for k in _COLUMNS})
    if a.json:
        a.json.write_text(json.dumps(rows, indent=2))
    if not a.quiet and not (a.csv or a.json):
        print(_render(rows), end="")

    by = {}
    for r in rows:
        if r["verdict"] != CLEAR:
            by[r["verdict"]] = by.get(r["verdict"], 0) + 1
    summ = ", ".join(f"{k}={v}" for k, v in sorted(by.items()))
    print(f"analysis_encryption: {n} file(s) scanned"
          + (f" - {summ}" if summ else " - nothing encrypted"), file=sys.stderr)
    enc = sum(v for k, v in by.items() if k in ("encrypted",
                                                "password-protected"))
    return 1 if enc else 0


if __name__ == "__main__":
    raise SystemExit(main())
