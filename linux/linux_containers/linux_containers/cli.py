from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from linux_containers import __version__, tracelib
from linux_containers.analyze import analyze
from linux_containers.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_containers",
        description="Reconstruct container activity from the on-disk runtime "
                    "state under a mounted image or a live root: Docker "
                    "(config.v2.json / hostconfig.json / json.log), Podman "
                    "(containers.json + OCI userdata/config.json) and "
                    "containerd (OCI config.json). One record per container: "
                    "engine, id, name, image, created / started / finished, "
                    "exit code, entrypoint + command, environment, bind "
                    "mounts, ports and the security posture. Flags privileged "
                    "containers, a mounted runtime socket, sensitive host "
                    "bind mounts, host namespaces, dangerous capabilities, "
                    "disabled seccomp / AppArmor, secret-looking env vars and "
                    "cradle entrypoints. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_containers /mnt/evidence\n"
                "  linux_containers / --csv containers.csv\n"
                "  linux_containers /mnt/img --engine docker --notable-only\n"
                "  linux_containers /mnt/img --min-severity high\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="filesystem root(s) to inspect (mounted image or /)")
    p.add_argument("--version", action="version",
                   version=f"linux_containers {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--engine", choices=["docker", "podman", "containerd"],
                   action="append", help="only this engine (repeatable)")
    p.add_argument("--state", help="only this state (running / exited / ...)")
    p.add_argument("--grep", metavar="REGEX",
                   help="match name / image / command / mounts / env")
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
        from linux_containers.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one path is required (or use --gui)")
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "linux_containers", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = analyze(strpaths)
    for s in res.sources:
        ctx.add_input(s)
    for e in res.errors:
        ctx.error("engine-error", e)

    engines = set(a.engine) if a.engine else None
    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for c in res.containers:
        r = row(c)
        if engines and r["engine"] not in engines:
            continue
        if a.state and r["state"] != a.state:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["name"], r["image"], r["entrypoint"], r["command"],
                r["mounts"], r["env"]))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.engines), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"linux_containers: {len(res.containers)} container(s) -> "
          f"{len(rows)} shown, {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
