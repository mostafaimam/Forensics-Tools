"""Synthetic log fixtures - representative real-world lines."""

from __future__ import annotations

from pathlib import Path

# BSD / RFC 3164 auth.log (Debian/Ubuntu style), no year in the timestamps
AUTH_LOG = """\
Feb 10 08:15:01 web01 CRON[20443]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 10 08:15:01 web01 CRON[20443]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 10 08:15:01 web01 CRON[20443]: pam_unix(cron:session): session closed for user root
Feb 10 09:02:11 web01 sshd[20512]: Accepted publickey for deploy from 203.0.113.9 port 55210 ssh2: RSA SHA256:abcd
Feb 10 09:02:11 web01 sshd[20512]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Feb 10 09:02:11 web01 systemd-logind[888]: New session 42 of user deploy.
Feb 10 09:07:44 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Feb 10 09:07:44 web01 sudo: pam_unix(sudo:session): session opened for user root by deploy(uid=1000)
Feb 10 09:15:22 web01 sshd[20890]: Invalid user admin from 198.51.100.23 port 40001
Feb 10 09:15:22 web01 sshd[20890]: Failed password for invalid user admin from 198.51.100.23 port 40001 ssh2
Feb 10 09:15:24 web01 sshd[20890]: Failed password for invalid user admin from 198.51.100.23 port 40001 ssh2
Feb 10 09:15:26 web01 sshd[20890]: message repeated 2 times: [ Failed password for invalid user admin from 198.51.100.23 port 40001 ssh2]
Feb 10 09:15:28 web01 sshd[20890]: Disconnecting authenticating user admin 198.51.100.23 port 40001: Too many authentication failures [preauth]
Feb 10 09:20:03 web01 sshd[21001]: Failed password for root from 198.51.100.23 port 40200 ssh2
Feb 10 09:20:59 web01 sshd[21001]: Connection closed by authenticating user root 198.51.100.23 port 40200 [preauth]
Feb 10 10:00:00 web01 su[21500]: pam_unix(su:auth): authentication failure; logname=deploy uid=1000 euid=0 tty=pts/0 ruser=deploy rhost=  user=root
Feb 10 10:00:05 web01 su[21500]: + pts/0 deploy:root
Feb 10 11:30:00 web01 useradd[22000]: new user: name=svc_backup, UID=997, GID=997, home=/nonexistent, shell=/usr/sbin/nologin
Feb 10 11:30:01 web01 passwd[22010]: password changed for svc_backup
Feb 10 12:00:00 web01 kernel: [12345.6789] usb 1-1: new high-speed USB device number 5 using xhci_hcd
Feb 10 12:00:00 web01 myapp[999]: Traceback (most recent call last):
  File "/opt/app/run.py", line 12, in <module>
    main()
RuntimeError: config value = 42 is invalid
Feb 10 13:00:00 web01 systemd-logind[888]: Removed session 42.
"""

# rsyslog "FileFormat" - ISO 8601 high precision with offset
SYSLOG_ISO = """\
2024-02-10T08:15:01.123456+00:00 web01 systemd[1]: Starting Daily apt download activities...
2024-02-10T08:15:02.001000+00:00 web01 systemd[1]: apt-daily.service: Succeeded.
2024-02-10T09:30:00.500000+02:00 web01 sshd[30000]: Accepted password for alice from 10.0.0.5 port 51000 ssh2
"""

# RFC 5424
RFC5424 = (
    "<34>1 2024-02-10T22:14:15.003Z mymachine.example.com su 1234 ID47 "
    "[timeQuality tzKnown=\"1\" isSynced=\"1\"] FAILED su for root by bob\n"
    "<165>1 2024-02-10T22:14:16.000Z web01 myapp 8710 - - an application event\n"
)


def write_tree(base: Path) -> Path:
    root = base / "img"
    log = root / "var" / "log"
    log.mkdir(parents=True, exist_ok=True)
    (log / "auth.log").write_text(AUTH_LOG)
    (log / "syslog").write_text(SYSLOG_ISO)
    import gzip
    (log / "auth.log.1").write_text(
        "Feb 03 04:00:00 web01 sshd[100]: Accepted password for carol "
        "from 10.0.0.9 port 40000 ssh2\n")
    with gzip.open(log / "auth.log.2.gz", "wt") as fh:
        fh.write("Jan 27 04:00:00 web01 sshd[99]: Accepted password for dave "
                 "from 10.0.0.10 port 40000 ssh2\n")
    return root
