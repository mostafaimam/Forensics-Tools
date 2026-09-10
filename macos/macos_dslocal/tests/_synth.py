"""Synthetic dslocal node for the macos_dslocal test-suite."""

from __future__ import annotations

import plistlib
from pathlib import Path


def _shadowhash(iters: int) -> bytes:
    return plistlib.dumps({
        "SALTED-SHA512-PBKDF2": {
            "entropy": b"\x00" * 128, "salt": b"\x11" * 32,
            "iterations": iters}})


def _account_policy(created, last_login, failed_ts, failed_count,
                    pw_set) -> bytes:
    return plistlib.dumps({
        "creationTime": created, "lastLoginTimestamp": last_login,
        "failedLoginTimestamp": failed_ts, "failedLoginCount": failed_count,
        "passwordLastSetTime": pw_set})


def _user(name, uid, gid, realname, home, shell, *, hint="", auth="shadow",
          iters=100000, ap=None):
    d = {
        "name": [name], "uid": [str(uid)], "gid": [str(gid)],
        "realname": [realname], "home": [home], "shell": [shell],
        "generateduid": [f"00000000-0000-0000-0000-{uid:012d}"],
        "passwd": ["********"],
    }
    if hint:
        d["hint"] = [hint]
    if auth == "shadow":
        d["authentication_authority"] = [
            ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"]
        d["ShadowHashData"] = [_shadowhash(iters)]
    elif auth == "none":
        d["authentication_authority"] = []
        d["passwd"] = [""]
    elif auth == "disabled":
        d["authentication_authority"] = [";DisabledUser;", ";ShadowHash;"]
        d["ShadowHashData"] = [_shadowhash(iters)]
    if ap:
        d["accountPolicyData"] = [_account_policy(*ap)]
    return d


def _group(name, gid, users):
    return {"name": [name], "gid": [str(gid)], "users": users,
            "realname": [name]}


def build_node(root: Path) -> Path:
    node = root / "private/var/db/dslocal/nodes/Default"
    (node / "users").mkdir(parents=True)
    (node / "groups").mkdir(parents=True)

    users = [
        _user("root", 0, 0, "System Administrator", "/var/root", "/bin/sh"),
        _user("_spotlight", 89, 89, "Spotlight", "/var/empty",
              "/usr/bin/false"),
        _user("victim", 501, 20, "Victim User", "/Users/victim", "/bin/zsh",
              hint="Fluffy2019!", auth="shadow", iters=200000,
              ap=(1700000000.0, 1741600000.0, 1741500000.0, 2,
                  1700100000.0)),
        _user("admin", 502, 20, "Local Admin", "/Users/admin", "/bin/bash",
              hint="ask IT", auth="shadow", iters=200000,
              ap=(1690000000.0, 1741700000.0, 0, 0, 1690000000.0)),
        # planted: hidden interactive account
        _user("svc-helper", 401, 401, "", "/var/svc", "/bin/bash",
              auth="shadow", iters=200000),
        # planted: passwordless account with a shell
        _user("guestx", 503, 20, "Guest", "/Users/guestx", "/bin/zsh",
              auth="none"),
        # planted: home outside /Users
        _user("backup", 504, 20, "Backup", "/opt/backup-home/backup",
              "/bin/zsh", auth="shadow", iters=200000),
    ]
    for u in users:
        (node / "users" / f"{u['name'][0]}.plist").write_bytes(
            plistlib.dumps(u))

    groups = [
        _group("admin", 80, ["root", "admin", "guestx"]),
        _group("staff", 20, ["victim", "admin", "backup"]),
    ]
    for g in groups:
        (node / "groups" / f"{g['name'][0]}.plist").write_bytes(
            plistlib.dumps(g))
    return root
