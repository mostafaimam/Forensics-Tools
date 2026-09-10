"""Build synthetic package-manager logs for the linux_packages test-suite."""

from __future__ import annotations

import gzip
import sqlite3
from pathlib import Path

DPKG_LOG = """\
2026-01-04 09:12:33 startup archives unpack
2026-01-04 09:12:34 install build-essential:amd64 <none> 12.9
2026-01-04 09:12:35 configure build-essential:amd64 12.9 <none>
2026-01-04 09:12:40 install gcc-12:amd64 <none> 12.3.0-1
2026-01-05 22:41:02 upgrade openssl:amd64 3.0.11-1 3.0.13-1
2026-01-06 02:03:17 install nmap:amd64 <none> 7.94-1
2026-01-06 02:55:44 remove nmap:amd64 7.94-1 <none>
2026-02-01 14:00:00 install tor:amd64 <none> 0.4.8.10-1
2026-02-10 03:14:00 install nmap:amd64 <none> 7.94-1
"""

APT_HISTORY = """\
Start-Date: 2026-01-04  09:12:30
Commandline: apt-get install -y build-essential
Requested-By: analyst (1000)
Install: build-essential:amd64 (12.9), gcc-12:amd64 (12.3.0-1, automatic)
End-Date: 2026-01-04  09:12:45

Start-Date: 2026-01-05  22:41:00
Commandline: /usr/bin/unattended-upgrade
Upgrade: openssl:amd64 (3.0.11-1, 3.0.13-1)
End-Date: 2026-01-05  22:41:05

Start-Date: 2026-01-08  11:00:00
Commandline: apt install ./sketchy_1.0_amd64.deb
Requested-By: root (0)
Install: sketchy:amd64 (1.0)
End-Date: 2026-01-08  11:00:04

Start-Date: 2026-01-09  01:22:00
Commandline: bash -c "apt-get -y install socat && systemctl restart x"
Install: socat:amd64 (1.7.4.4-2)
End-Date: 2026-01-09  01:22:09
"""

YUM_LOG = """\
Jan 04 09:12:34 2026 Installed: httpd-2.4.57-5.el9.x86_64
Jan 05 22:41:02 2026 Updated: openssl-1:3.0.7-24.el9.x86_64
Jan 06 02:03:17 2026 Installed: nmap-3:7.92-1.el9.x86_64
Jan 06 02:55:44 2026 Erased: nmap-3:7.92-1.el9.x86_64
Jan 07 08:00:00 2026 Downgraded: sudo-1.9.5p2-7.el9.x86_64
"""

DNF_LOG = """\
2026-01-04T09:12:34+0000 INFO Installed: git-2.43.0-1.fc39.x86_64
2026-01-06T02:03:17+0000 INFO Installed: socat-1.7.4.4-3.fc39.x86_64
2026-01-06T05:20:00+0000 INFO Removed: socat-1.7.4.4-3.fc39.x86_64
2026-01-10T12:00:00+0000 INFO Upgraded: kernel-6.7.4-200.fc39.x86_64
"""


def _w(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def dpkg_log(root: Path, text: str = DPKG_LOG) -> Path:
    return _w(root, "var/log/dpkg.log", text)


def dpkg_log_gz(root: Path, text: str, name: str = "dpkg.log.1.gz") -> Path:
    p = root / "var/log" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(gzip.compress(text.encode()))
    return p


def apt_history(root: Path, text: str = APT_HISTORY) -> Path:
    return _w(root, "var/log/apt/history.log", text)


def yum_log(root: Path, text: str = YUM_LOG) -> Path:
    return _w(root, "var/log/yum.log", text)


def dnf_log(root: Path, text: str = DNF_LOG) -> Path:
    return _w(root, "var/log/dnf.log", text)


def dnf_history(root: Path) -> Path:
    """A minimal dnf history.sqlite: two transactions, four items."""
    p = root / "var/lib/dnf/history.sqlite"
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.executescript(
        "CREATE TABLE trans (id INTEGER PRIMARY KEY, dt_begin INTEGER, "
        "cmdline TEXT, loginuid INTEGER);"
        "CREATE TABLE rpm (item_id INTEGER PRIMARY KEY, name TEXT, "
        "epoch TEXT, version TEXT, release TEXT, arch TEXT);"
        "CREATE TABLE trans_item (id INTEGER PRIMARY KEY, trans_id INTEGER, "
        "item_id INTEGER, action INTEGER, reason INTEGER, state INTEGER);"
    )
    con.execute("INSERT INTO trans VALUES (1, 1767517954, "
                "'dnf install hashcat', 1000)")            # 2026-01-04 09:12:34Z
    con.execute("INSERT INTO trans VALUES (2, 1767666000, "
                "'dnf install openvpn', 0)")
    con.executemany("INSERT INTO rpm VALUES (?,?,?,?,?,?)", [
        (10, "hashcat", "0", "6.2.6", "3.fc39", "x86_64"),
        (11, "zlib", "0", "1.3", "1.fc39", "x86_64"),
        (12, "openvpn", "0", "2.6.9", "1.fc39", "x86_64"),
    ])
    con.executemany(
        "INSERT INTO trans_item (trans_id, item_id, action, reason, state) "
        "VALUES (?,?,?,?,?)", [
            (1, 10, 1, 1, 1),   # install hashcat
            (1, 11, 1, 2, 1),   # install zlib (dep)
            (2, 12, 1, 1, 1),   # install openvpn
        ])
    con.commit()
    con.close()
    return p
