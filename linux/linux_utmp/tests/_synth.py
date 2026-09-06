"""Build synthetic utmp / wtmp / lastlog records."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

RECORD_SIZE = 384
LASTLOG_SIZE = 292

EMPTY = 0
BOOT_TIME = 2
LOGIN_PROCESS = 6
USER_PROCESS = 7
DEAD_PROCESS = 8


def _epoch(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def utmp_record(*, ut_type: int, pid: int = 0, line: str = "", ut_id: str = "",
                user: str = "", host: str = "", when: datetime | None = None,
                ipv4: str | None = None, session: int = 0,
                e_term: int = 0, e_exit: int = 0) -> bytes:
    b = bytearray(RECORD_SIZE)
    struct.pack_into("<h", b, 0, ut_type)
    struct.pack_into("<i", b, 4, pid)
    b[8:8 + len(line)] = line.encode()
    b[40:40 + len(ut_id)] = ut_id.encode()
    b[44:44 + len(user)] = user.encode()
    b[76:76 + len(host)] = host.encode()
    struct.pack_into("<hh", b, 332, e_term, e_exit)
    struct.pack_into("<i", b, 336, session)
    if when:
        struct.pack_into("<II", b, 340, _epoch(when), 0)
    if ipv4:
        parts = [int(x) for x in ipv4.split(".")]
        struct.pack_into("<I", b, 348,
                         parts[0] | parts[1] << 8 | parts[2] << 16 | parts[3] << 24)
    return bytes(b)


def wtmp(records: list[bytes]) -> bytes:
    return b"".join(records)


def lastlog_entry(uid: int, when: datetime | None, line: str, host: str) -> bytes:
    b = bytearray(LASTLOG_SIZE)
    struct.pack_into("<I", b, 0, _epoch(when) if when else 0)
    b[4:4 + len(line)] = line.encode()
    b[36:36 + len(host)] = host.encode()
    return bytes(b)


def lastlog(entries: dict[int, tuple]) -> bytes:
    max_uid = max(entries) if entries else 0
    out = bytearray()
    for uid in range(max_uid + 1):
        if uid in entries:
            when, line, host = entries[uid]
            out += lastlog_entry(uid, when, line, host)
        else:
            out += b"\x00" * LASTLOG_SIZE
    return bytes(out)


def sample_wtmp() -> bytes:
    t0 = datetime(2024, 3, 1, 8, 0, 0)
    from datetime import timedelta
    return wtmp([
        utmp_record(ut_type=BOOT_TIME, line="~", user="reboot",
                    when=t0),
        utmp_record(ut_type=USER_PROCESS, pid=2001, line="pts/0", ut_id="ts/0",
                    user="alice", host="10.0.0.5", ipv4="10.0.0.5",
                    when=t0 + timedelta(minutes=5)),
        utmp_record(ut_type=USER_PROCESS, pid=2100, line="pts/1", ut_id="ts/1",
                    user="bob", host="192.168.1.9", ipv4="192.168.1.9",
                    when=t0 + timedelta(minutes=10)),
        utmp_record(ut_type=DEAD_PROCESS, pid=2001, line="pts/0",
                    when=t0 + timedelta(minutes=42)),
        utmp_record(ut_type=USER_PROCESS, pid=2200, line="pts/0", ut_id="ts/0",
                    user="alice", host="10.0.0.5", ipv4="10.0.0.5",
                    when=t0 + timedelta(hours=2)),
        # bob never logs out
    ])


def sample_btmp() -> bytes:
    from datetime import timedelta
    t0 = datetime(2024, 3, 1, 3, 0, 0)
    return wtmp([
        utmp_record(ut_type=LOGIN_PROCESS, pid=999, line="ssh:notty",
                    user="root", host="45.9.148.2", ipv4="45.9.148.2",
                    when=t0 + timedelta(seconds=i * 7))
        for i in range(5)
    ])
