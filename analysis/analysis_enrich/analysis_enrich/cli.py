from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analysis_enrich import __version__, tracelib
from analysis_enrich.enrich import enrich, write


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_enrich",
        description="Enrich an analysis_timeline bundle (CSV / JSON / JSONL) "
                    "by appending columns: matched IOCs from supplied feeds, "
                    "MITRE ATT&CK technique ids from a bundled map, a coarse "
                    "geo region for public IPs, and known-good/bad for "
                    "hashes. Rows and order are preserved.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  analysis_enrich timeline.csv --feed iocs.txt -o enriched.csv\n"
                "  analysis_enrich tl.jsonl --feed c2.csv --feed hashes.json "
                "--known-csv kff.csv -o tl.enriched.jsonl\n"
                "  analysis_enrich timeline.csv --no-attack --geo-csv "
                "geoip.csv -o out.csv\n"))
    p.add_argument("timeline", type=Path)
    p.add_argument("--version", action="version",
                   version=f"analysis_enrich {__version__}")
    p.add_argument("--feed", action="append", default=[], metavar="FILE",
                   help="IOC feed (plain list / CSV / STIX-lite JSON); "
                        "repeatable")
    p.add_argument("--geo-csv", metavar="FILE",
                   help="a 'cidr,label' table for IP geolocation")
    p.add_argument("--known-csv", metavar="FILE",
                   help="a 'hash,label' list (good / bad / ...)")
    p.add_argument("--no-attack", action="store_true",
                   help="skip ATT&CK tagging")
    p.add_argument("-o", "--out", type=Path, required=True,
                   help="the enriched output (same format as the input)")
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.timeline.exists():
        print(f"not found: {a.timeline}", file=sys.stderr)
        return 2
    for f in a.feed + ([a.geo_csv] if a.geo_csv else []) + \
            ([a.known_csv] if a.known_csv else []):
        if f and not Path(f).exists():
            print(f"not found: {f}", file=sys.stderr)
            return 2

    ctx = tracelib.context(a, "analysis_enrich", __version__)
    try:
        ctx.limits.check_paths([str(a.timeline)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.timeline))
    for f in a.feed:
        ctx.add_input(f)

    res = enrich(str(a.timeline), feed_paths=a.feed, geo_csv=a.geo_csv,
                 known_csv=a.known_csv, attack_on=not a.no_attack)
    write(res, str(a.out))

    if not a.quiet:
        top = sorted(res.technique_counts.items(), key=lambda kv: -kv[1])[:10]
        print(f"rows            {len(res.rows)}")
        print(f"IOC matches     {res.ioc_hits}")
        print(f"ATT&CK-tagged   {res.attack_hits}")
        if res.known_bad:
            print(f"known-bad hash  {res.known_bad}")
        if top:
            print("top techniques:")
            for tid, n in top:
                print(f"  {tid}  x{n}")
    ctx.finish(outputs=[a.out])
    print(f"analysis_enrich: wrote {a.out} (+{len(res.columns)} cols, "
          f"{res.ioc_hits} IOC, {res.attack_hits} ATT&CK)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
