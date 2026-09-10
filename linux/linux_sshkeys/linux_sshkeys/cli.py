from __future__ import annotations

import argparse
import sys
from pathlib import Path

from linux_sshkeys import __version__, tracelib
from linux_sshkeys.collect import collect
from linux_sshkeys.output import COLUMNS, render, rows

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_sshkeys",
        description="Review SSH keys, known hosts and sshd configuration under "
                    "a mounted image or a live root. Inventories every "
                    "authorized_keys (system + per-user), host key and its "
                    "private key (format + encryption only), known_hosts entry "
                    "(hashed entries noted) and sshd_config directive "
                    "(including sshd_config.d and Match blocks). Reports the "
                    "key type, bit size, comment and SHA256 / MD5 "
                    "fingerprints. Flags wildcard from=, forced command=, "
                    "environment=, weak / short keys, @cert-authority trust, "
                    "world-writable key files and permissive sshd settings. "
                    "Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_sshkeys /mnt/evidence\n"
                "  linux_sshkeys / --csv sshkeys.csv\n"
                "  linux_sshkeys /mnt/img --notable-only --min-severity high\n"
                "  linux_sshkeys /mnt/img --kind authorized_key\n"))
    p.add_argument("root", nargs="?", type=Path,
                   help="filesystem root to review (mounted image or /)")
    p.add_argument("--version", action="version",
                   version=f"linux_sshkeys {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", choices=["authorized_key", "known_host",
                                      "host_key", "private_key",
                                      "config-finding", "config"],
                   help="only this kind of row")
    p.add_argument("--user", help="only authorized_keys for this user")
    p.add_argument("--all-directives", action="store_true",
                   help="also emit every sshd_config directive (not just the "
                        "review findings)")
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
        from linux_sshkeys.gui import run_gui
        return run_gui([str(a.root)] if a.root else [])
    if not a.root:
        build_parser().error("a filesystem root is required (or use --gui)")
    if not a.root.exists():
        print(f"not found: {a.root}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "linux_sshkeys", __version__)
    try:
        ctx.limits.check_paths([str(a.root)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(str(a.root))
    for f in res.files:
        ctx.add_input(f)
    for e in res.errors:
        ctx.error("read-error", e)

    allrows = rows(res, include_config_directives=a.all_directives)
    out = []
    for r in allrows:
        if a.kind and r["kind"] != a.kind:
            continue
        if a.user and r["kind"] == "authorized_key" and r["user"] != a.user:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV.get(r["severity"] or "none", 0) < \
                _SEV[a.min_severity]:
            continue
        out.append(r)

    if a.csv:
        tracelib.write_csv(out, a.csv, COLUMNS, ctx,
                           confidence="high", tz="no-timezone")
    if a.json:
        tracelib.write_json(out, a.json, ctx,
                            confidence="high", tz="no-timezone")
    if not a.quiet and not (a.csv or a.json):
        print(render(res), end="")

    ctx.finish(outputs=[a.csv, a.json])
    nflag = sum(1 for r in out if r["notable"])
    print(f"linux_sshkeys: {len(res.keys)} key(s), {len(res.private)} private "
          f"key(s), {len(res.config_findings)} config finding(s) -> "
          f"{len(out)} row(s), {nflag} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if out else 1


if __name__ == "__main__":
    raise SystemExit(main())
