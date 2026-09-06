from datetime import datetime, timezone

from linux_syslog.events import extract
from linux_syslog.parser import parse_line

REF = datetime(2024, 6, 1, tzinfo=timezone.utc)
UTC = timezone.utc


def ev(line):
    return extract(parse_line(line, ref_date=REF, assume_tz=UTC))


def test_ssh_accepted():
    e = ev("Feb 10 09:02:11 h sshd[1]: Accepted publickey for deploy "
           "from 203.0.113.9 port 55210 ssh2: RSA SHA256:x")
    assert e.category == "ssh" and e.action == "login" and e.result == "success"
    assert e.user == "deploy" and e.source_ip == "203.0.113.9"
    assert e.source_port == "55210" and "publickey" in e.detail


def test_ssh_failed_invalid_user():
    e = ev("Feb 10 09:15:22 h sshd[1]: Failed password for invalid user admin "
           "from 198.51.100.23 port 40001 ssh2")
    assert e.result == "failure" and e.user == "admin"
    assert "invalid user" in e.detail


def test_ssh_repeat():
    e = ev("Feb 10 09:15:26 h sshd[1]: message repeated 2 times: [ Failed "
           "password for invalid user admin from 198.51.100.23 port 40001 ssh2]")
    assert e.result == "failure" and e.detail == "repeated 2x"


def test_sudo_command():
    e = ev("Feb 10 09:07:44 h sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; "
           "USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
    assert e.category == "sudo" and e.user == "deploy"
    assert e.target_user == "root" and e.command.endswith("restart nginx")
    assert e.tty == "pts/0"


def test_su_switch():
    e = ev("Feb 10 10:00:05 h su[1]: + pts/0 deploy:root")
    assert e.category == "su" and e.result == "success"
    assert e.user == "deploy" and e.target_user == "root"


def test_session_new_removed():
    a = ev("Feb 10 09:02:11 h systemd-logind[8]: New session 42 of user deploy.")
    assert a.category == "session" and a.action == "open" and a.user == "deploy"
    b = ev("Feb 10 13:00:00 h systemd-logind[8]: Removed session 42.")
    assert b.action == "close"


def test_cron_run():
    e = ev("Feb 10 08:15:01 h CRON[2]: (root) CMD (   /usr/bin/backup)")
    assert e.category == "cron" and e.user == "root"
    assert e.command.strip() == "/usr/bin/backup"


def test_account_useradd():
    e = ev("Feb 10 11:30:00 h useradd[1]: new user: name=svc_backup, UID=997, "
           "GID=997, home=/nonexistent, shell=/usr/sbin/nologin")
    assert e.category == "account" and e.action == "user-add"
    assert e.target_user == "svc_backup"


def test_pam_generic_failure():
    e = ev("Feb 10 10:00:00 h su[1]: pam_unix(su:auth): authentication failure; "
           "logname=deploy uid=1000 euid=0 tty=pts/0 ruser=deploy rhost= user=root")
    # the su-specific rule wins, but must still be a failure with the target
    assert e.result == "failure"


def test_non_event_returns_none():
    assert ev("Feb 10 12:00:00 h myapp[9]: starting job") is None
