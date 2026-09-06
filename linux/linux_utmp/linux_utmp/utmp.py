"""Parse the Linux ``utmp`` / ``wtmp`` / ``btmp`` binary login-record format.

``struct utmp`` on Linux (glibc, 64-bit), 384 bytes::

    0x000  int16   ut_type            (+ 2 bytes padding)
    0x004  int32   ut_pid
    0x008  char[32] ut_line           controlling terminal
    0x028  char[4]  ut_id
    0x02c  char[32] ut_user
    0x04c  char[256] ut_host
    0x14c  int16   ut_exit.e_termination
    0x14e  int16   ut_exit.e_exit
    0x150  int32   ut_session
    0x154  int32   tv_sec
    0x158  int32   tv_usec
    0x15c  int32[4] ut_addr_v6         IPv4 in [0]; full IPv6 uses all four
    0x16c  char[20] __glibc_reserved

The same structure is used by ``utmp`` (current sessions), ``wtmp`` (history)
and ``btmp`` (failed logins).
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

RECORD_SIZE = 384

UT_TYPES = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS",
    8: "DEAD_PROCESS", 9: "ACCOUNTING",
}


class UtmpError(ValueError):
    pass


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


@dataclass
class UtmpRecord:
    index: int
    type_id: int
    pid: int
    line: str
    ut_id: str
    user: str
    host: str
    session: int
    exit_termination: int
    exit_code: int
    timestamp: datetime | None
    address: str

    @property
    def type_name(self) -> str:
        return UT_TYPES.get(self.type_id, f"TYPE_{self.type_id}")


def _addr(raw: bytes, big_endian: bool) -> str:
    order = ">" if big_endian else "<"
    a = struct.unpack_from(f"{order}4I", raw, 0)
    if a[1] == 0 == a[2] == a[3]:
        if a[0] == 0:
            return ""
        return str(ipaddress.IPv4Address(struct.pack("<I", a[0])))
    packed = struct.pack(f"{order}4I", *a)
    try:
        return str(ipaddress.IPv6Address(packed))
    except ValueError:
        return raw.hex()


def parse_record(chunk: bytes, index: int, big_endian: bool = False) -> UtmpRecord:
    if len(chunk) < RECORD_SIZE:
        raise UtmpError(f"record {index} truncated ({len(chunk)} bytes)")
    o = ">" if big_endian else "<"
    ut_type = struct.unpack_from(f"{o}h", chunk, 0)[0]
    pid = struct.unpack_from(f"{o}i", chunk, 4)[0]
    line = _cstr(chunk[8:40])
    ut_id = _cstr(chunk[40:44])
    user = _cstr(chunk[44:76])
    host = _cstr(chunk[76:332])
    e_term, e_exit = struct.unpack_from(f"{o}hh", chunk, 332)
    session = struct.unpack_from(f"{o}i", chunk, 336)[0]
    tv_sec, tv_usec = struct.unpack_from(f"{o}II", chunk, 340)
    addr = _addr(chunk[348:364], big_endian)

    ts = None
    if tv_sec:
        try:
            ts = datetime.fromtimestamp(tv_sec + tv_usec / 1_000_000,
                                        tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            ts = None

    return UtmpRecord(index, ut_type, pid, line, ut_id, user, host, session,
                      e_term, e_exit, ts, addr)


def parse(data: bytes, big_endian: bool = False):
    """Yield every :class:`UtmpRecord` in a wtmp/btmp/utmp byte string."""
    n = len(data)
    if n % RECORD_SIZE:
        # tolerate a trailing partial record
        n -= n % RECORD_SIZE
    for i in range(0, n, RECORD_SIZE):
        try:
            yield parse_record(data[i:i + RECORD_SIZE], i // RECORD_SIZE,
                               big_endian)
        except UtmpError:
            continue


def looks_like_utmp(data: bytes) -> bool:
    if len(data) < RECORD_SIZE or len(data) % RECORD_SIZE:
        return False
    ok = 0
    for rec in list(parse(data))[:8]:
        if rec.type_id in UT_TYPES and (rec.timestamp or rec.type_id == 0):
            ok += 1
    return ok >= 1
