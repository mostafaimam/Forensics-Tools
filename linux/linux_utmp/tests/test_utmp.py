from datetime import timezone

from _synth import lastlog, sample_btmp, sample_wtmp, utmp_record
from linux_utmp.lastlog import parse as parse_lastlog
from linux_utmp.sessions import build_sessions
from linux_utmp.utmp import looks_like_utmp
from linux_utmp.utmp import parse as parse_utmp
from datetime import datetime


def test_parse_records():
    recs = list(parse_utmp(sample_wtmp()))
    assert len(recs) == 5
    assert recs[0].type_name == "BOOT_TIME"
    a = recs[1]
    assert a.type_name == "USER_PROCESS"
    assert a.user == "alice" and a.line == "pts/0"
    assert a.address == "10.0.0.5"
    assert a.timestamp.tzinfo == timezone.utc
    assert a.timestamp.hour == 8 and a.timestamp.minute == 5


def test_looks_like_utmp():
    assert looks_like_utmp(sample_wtmp())
    assert not looks_like_utmp(b"not a utmp file at all, random bytes here")


def test_sessions_pairing():
    recs = list(parse_utmp(sample_wtmp()))
    sess = build_sessions(recs)
    assert len(sess) == 3
    alice1 = sess[0]
    assert alice1.user == "alice" and alice1.line == "pts/0"
    assert alice1.logout is not None
    assert abs(alice1.duration_seconds - 37 * 60) < 1
    bob = sess[1]
    assert bob.user == "bob" and bob.still_open
    assert bob.duration_seconds is None


def test_boot_time_closes_open_sessions():
    data = b"".join([
        utmp_record(ut_type=7, line="pts/0", user="x",
                    when=datetime(2024, 1, 1, 10, 0)),
        utmp_record(ut_type=2, line="~", user="reboot",
                    when=datetime(2024, 1, 1, 11, 0)),
    ])
    sess = build_sessions(list(parse_utmp(data)))
    assert len(sess) == 1
    assert sess[0].logout is not None and not sess[0].still_open


def test_btmp_failed_logins():
    recs = list(parse_utmp(sample_btmp()))
    assert len(recs) == 5
    assert all(r.user == "root" and r.address == "45.9.148.2" for r in recs)


def test_lastlog():
    data = lastlog({
        0: (datetime(2024, 2, 1, 9, 0), "console", ""),
        1000: (datetime(2024, 2, 3, 14, 30), "pts/2", "workstation.lan"),
    })
    entries = {e.uid: e for e in parse_lastlog(data)}
    assert set(entries) == {0, 1000}
    assert entries[1000].host == "workstation.lan"
    assert entries[1000].timestamp.day == 3


def test_partial_trailing_record_tolerated():
    data = sample_wtmp() + b"\x07\x00\x00"       # 3 stray bytes
    assert len(list(parse_utmp(data))) == 5
