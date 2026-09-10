"""Discover and parse every supported network-config file under a root."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from linux_networkmgr import flags as _flags
from linux_networkmgr import parse as _parse


@dataclass
class Result:
    items: list = field(default_factory=list)
    files: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _read(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def collect(root_str: str) -> Result:
    res = Result()
    root = Path(root_str)

    nmdir = root / "etc/NetworkManager/system-connections"
    if nmdir.is_dir():
        for p in sorted(nmdir.iterdir()):
            if not p.is_file():
                continue
            txt = _read(p)
            if txt is None:
                res.errors.append(f"unreadable: {p}")
                continue
            res.files.append(str(p))
            res.items.append(_parse.parse_nmconnection(txt, str(p)))

    for p in sorted((root / "etc/wpa_supplicant").glob("wpa_supplicant*.conf")) \
            if (root / "etc/wpa_supplicant").is_dir() else []:
        txt = _read(p)
        if txt is not None:
            res.files.append(str(p))
            res.items += _parse.parse_wpa_supplicant(txt, str(p))

    for p in sorted((root / "etc/systemd/network").glob("*.network")) \
            if (root / "etc/systemd/network").is_dir() else []:
        txt = _read(p)
        if txt is not None:
            res.files.append(str(p))
            res.items.append(_parse.parse_networkd(txt, str(p)))

    for p in sorted((root / "etc/netplan").glob("*.yaml")) \
            if (root / "etc/netplan").is_dir() else []:
        txt = _read(p)
        if txt is not None:
            res.files.append(str(p))
            res.items += _parse.parse_netplan(txt, str(p))

    hosts = root / "etc/hosts"
    if hosts.is_file():
        txt = _read(hosts)
        if txt is not None:
            res.files.append(str(hosts))
            res.items += _parse.parse_hosts(txt, str(hosts))

    for rel in ("etc/resolv.conf", "run/systemd/resolve/resolv.conf",
                "run/systemd/resolve/stub-resolv.conf"):
        p = root / rel
        if p.is_file():
            txt = _read(p)
            if txt is not None:
                res.files.append(str(p))
                res.items.append(_parse.parse_resolv(txt, str(p)))

    for it in res.items:
        it.notable = _flags.flag(it)

    res.items.sort(key=lambda i: (i.kind, i.name))
    return res
