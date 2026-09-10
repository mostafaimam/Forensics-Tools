"""Discover and review the SSH material under a filesystem root."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from linux_sshkeys import flags as _flags
from linux_sshkeys import keys as _keys
from linux_sshkeys import sshdconfig as _cfg


@dataclass
class Result:
    keys: list = field(default_factory=list)          # SshKey
    private: list = field(default_factory=list)       # PrivateKey
    directives: list = field(default_factory=list)    # Directive
    config_findings: list = field(default_factory=list)
    files: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _read(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _perm(p: Path):
    # POSIX mode bits are only meaningful when the host preserves them;
    # on Windows they are synthesised and would raise false flags.
    if os.name == "nt":
        return False, False, False
    try:
        m = p.stat().st_mode
        return bool(m & stat.S_IROTH), bool(m & stat.S_IRGRP), \
            bool(m & (stat.S_IWGRP | stat.S_IWOTH))
    except OSError:
        return False, False, False


def _iter_authorized(root: Path):
    home = root / "home"
    cands = []
    if (root / "root/.ssh").is_dir():
        cands.append(("root", root / "root/.ssh"))
    if home.is_dir():
        for d in home.iterdir():
            if (d / ".ssh").is_dir():
                cands.append((d.name, d / ".ssh"))
    for user, sshdir in cands:
        for name in ("authorized_keys", "authorized_keys2"):
            p = sshdir / name
            if p.is_file():
                yield user, p
    # AuthorizedKeysFile may point elsewhere; also scan /etc/ssh/authorized_keys
    for p in (root / "etc/ssh").glob("authorized_keys*"):
        if p.is_file():
            yield "(system)", p


def collect(root_str: str) -> Result:
    res = Result()
    root = Path(root_str)

    # authorized_keys ---------------------------------------------------------
    for user, p in _iter_authorized(root):
        txt = _read(p)
        if txt is None:
            res.errors.append(f"unreadable: {p}")
            continue
        res.files.append(str(p))
        wr, gr, writ = _perm(p)
        rel = str(p)
        in_dotssh = "/.ssh/" in rel.replace("\\", "/")
        for k in _keys.parse_authorized_keys(txt, rel, user):
            k.notable = _flags.flag_key(k)
            if writ:
                k.notable.append("authorized_keys file is group/other-writable")
            if not in_dotssh and user != "(system)":
                k.notable.append("authorized_keys outside a ~/.ssh directory")
            res.keys.append(k)

    # known_hosts -----------------------------------------------------------
    kh_paths = list((root / "etc/ssh").glob("ssh_known_hosts*"))
    for base in ("root/.ssh", ):
        kh_paths += list((root / base).glob("known_hosts*"))
    if (root / "home").is_dir():
        for d in (root / "home").iterdir():
            kh_paths += list((d / ".ssh").glob("known_hosts*"))
    for p in kh_paths:
        if not p.is_file():
            continue
        txt = _read(p)
        if txt is None:
            continue
        res.files.append(str(p))
        for k in _keys.parse_known_hosts(txt, str(p)):
            k.notable = _flags.flag_key(k)
            res.keys.append(k)

    # host keys + private keys --------------------------------------------
    etcssh = root / "etc/ssh"
    if etcssh.is_dir():
        for p in etcssh.glob("ssh_host_*_key.pub"):
            txt = _read(p)
            if txt:
                res.files.append(str(p))
                k = _keys.parse_host_pub(txt, str(p))
                if k:
                    k.notable = _flags.flag_key(k)
                    res.keys.append(k)
        for p in etcssh.glob("ssh_host_*_key"):
            _priv(p, res)
    # user private keys
    for d in [root / "root/.ssh"] + (
            list((root / "home").glob("*/.ssh")) if (root / "home").is_dir()
            else []):
        if d.is_dir():
            for p in d.iterdir():
                if p.is_file() and (p.name.startswith("id_")
                                    or p.name.endswith(".pem")):
                    _priv(p, res)

    # sshd_config ---------------------------------------------------------
    cfgs = []
    for c in ("etc/ssh/sshd_config",):
        p = root / c
        if p.is_file():
            cfgs.append(p)
    cfgs += sorted((root / "etc/ssh/sshd_config.d").glob("*.conf")) \
        if (root / "etc/ssh/sshd_config.d").is_dir() else []
    for p in cfgs:
        txt = _read(p)
        if txt is None:
            continue
        res.files.append(str(p))
        ds = _cfg.parse(txt, str(p))
        res.directives += ds
        res.config_findings += _cfg.review(ds)

    return res


def _priv(p: Path, res: Result):
    txt = _read(p)
    if txt is None:
        return
    pk = _keys.parse_private_key(txt, str(p))
    if pk is None:
        return
    res.files.append(str(p))
    wr, gr, _w = _perm(p)
    pk.notable = _flags.flag_private(pk, world_readable=wr, group_readable=gr)
    res.private.append(pk)
