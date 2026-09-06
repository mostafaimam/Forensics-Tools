from datetime import datetime, timezone

from linux_syslog.parser import parse_line

REF = datetime(2024, 6, 1, tzinfo=timezone.utc)
UTC = timezone.utc


def p(line, **kw):
    return parse_line(line, ref_date=REF, assume_tz=UTC, **kw)


def test_bsd_basic():
    r = p("Feb 10 09:02:11 web01 sshd[20512]: Accepted publickey for deploy")
    assert r.format == "bsd"
    assert r.timestamp == datetime(2024, 2, 10, 9, 2, 11, tzinfo=UTC)
    assert r.host == "web01" and r.tag == "sshd" and r.pid == "20512"
    assert r.message == "Accepted publickey for deploy"


def test_bsd_no_pid_and_pri():
    r = p("<38>Feb 10 09:07:44 web01 sudo:   deploy : TTY=pts/0 ; USER=root")
    assert r.facility == "auth" and r.severity == "info"
    assert r.tag == "sudo" and r.pid == ""
    assert r.message.startswith("  deploy : TTY=pts/0")


def test_bsd_previous_year_rollover():
    # ref is June 2024; a December line must be 2023
    r = p("Dec 25 00:00:00 web01 cron[1]: hello")
    assert r.timestamp.year == 2023


def test_iso_format_with_offset():
    r = p("2024-02-10T09:30:00.500000+02:00 web01 sshd[30000]: Accepted password")
    assert r.format == "iso"
    assert r.timestamp == datetime(2024, 2, 10, 7, 30, 0, 500000, tzinfo=UTC)
    assert r.tag == "sshd"


def test_rfc5424():
    r = p("<34>1 2024-02-10T22:14:15.003Z host su 1234 ID47 "
          "[timeQuality tzKnown=\"1\"] FAILED su for root by bob")
    assert r.format == "5424"
    assert r.timestamp == datetime(2024, 2, 10, 22, 14, 15, 3000, tzinfo=UTC)
    assert r.host == "host" and r.tag == "su" and r.pid == "1234"
    assert r.message == "FAILED su for root by bob"


def test_continuation_line():
    r = p("    config value = 42")
    assert r.timestamp is None and r.format == "continuation"
