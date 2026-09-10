from __future__ import annotations

import argparse
import sys
from pathlib import Path

from macos_dslocal import __version__, tracelib
from macos_dslocal import flags as _flags
from macos_dslocal.parse import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["uid", "name", "gid", "realname", "home", "shell", "generateduid",
           "hint", "auth", "pbkdf2_iterations", "created", "last_login",
           "last_failed_login", "failed_count", "password_last_set", "groups",
           "is_admin", "severity", "source", "notable"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_dslocal",
        description="Parse the /var/db/dslocal local Directory Services node. "
                    "One row per user: name, uid, gid, real name, home, "
                    "shell, generateduid, the password hint, the configured "
                    "authentication mechanisms (ShadowHash / Kerberos / SRP "
                    "/ SecureToken / crypt-hash / none), the PBKDF2 "
                    "iteration count, and - from accountPolicyData - the "
                    "account creation / last-login / last-failed-login / "
                    "password-last-set times (UTC) and the failed-login "
                    "count. Group membership is resolved (admin in "
                    "particular). No hash material is printed and nothing "
                    "is cracked. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_dslocal /Volumes/Macintosh\\ HD --csv users.csv\n"
                "  macos_dslocal _victim.plist --json u.json\n"
                "  macos_dslocal /mnt/mac --admins-only\n"
                "  macos_dslocal /mnt/mac --notable-only --min-severity high\n"))
    p.add_argument("path", type=Path,
                   help="a mounted macOS volume, a dslocal node, or a "
                        "user plist")
    p.add_argument("--version", action="version",
                   version=f"macos_dslocal {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--admins-only", action="store_true")
    p.add_argument("--include-service", action="store_true",
                   help="include the _service accounts (hidden by default)")
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
        from macos_dslocal.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_dslocal", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.path))

    res = collect(str(a.path))
    for e in res.errors:
        ctx.error("dslocal-error", e)
    if not res.users:
        print("no user records found", file=sys.stderr)
        return 2

    rows = []
    for u in res.users:
        r = u.row()
        r["severity"] = _flags.severity(u.notable)
        service = u.name.startswith("_")
        if not a.include_service and service and not r["notable"]:
            continue
        if a.admins_only and not u.is_admin:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
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
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            adm = " (admin)" if r["is_admin"] else ""
            print(f"{r['uid']:>6}  {r['name']:<20} {r['realname']:<24} "
                  f"{r['shell']:<12} [{r['auth']}]{adm}{mark}")
            for f in ("created", "last_login", "password_last_set"):
                if r[f]:
                    print(f"      {f}: {r[f]}")
            if r["hint"]:
                print(f"      hint: {r['hint']}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"      ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_dslocal: {len(res.users)} user(s), {len(res.groups)} "
          f"group(s) -> {len(rows)} shown, {fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
