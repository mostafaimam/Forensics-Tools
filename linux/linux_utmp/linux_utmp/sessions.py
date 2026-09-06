"""Pair login / logout records from wtmp into sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from linux_utmp.utmp import UtmpRecord


@dataclass
class Session:
    user: str
    line: str
    host: str
    address: str
    pid: int
    login: datetime | None
    logout: datetime | None
    login_index: int
    logout_index: int | None

    @property
    def duration_seconds(self) -> float | None:
        if self.login and self.logout:
            return (self.logout - self.login).total_seconds()
        return None

    @property
    def still_open(self) -> bool:
        return self.logout is None


def build_sessions(records: list[UtmpRecord]) -> list[Session]:
    """USER_PROCESS (7) opens a session on a tty; DEAD_PROCESS (8) on the same
    tty closes the most recent open one.  BOOT_TIME (2) closes everything."""
    open_by_line: dict[str, Session] = {}
    sessions: list[Session] = []

    for rec in records:
        if rec.type_id == 2:                       # BOOT_TIME
            for s in open_by_line.values():
                s.logout = rec.timestamp
                s.logout_index = rec.index
            open_by_line.clear()
            continue
        if rec.type_id == 7 and rec.user:          # USER_PROCESS
            s = Session(
                user=rec.user, line=rec.line, host=rec.host,
                address=rec.address, pid=rec.pid,
                login=rec.timestamp, logout=None,
                login_index=rec.index, logout_index=None,
            )
            open_by_line[rec.line] = s
            sessions.append(s)
        elif rec.type_id == 8:                     # DEAD_PROCESS
            s = open_by_line.pop(rec.line, None)
            if s is not None:
                s.logout = rec.timestamp
                s.logout_index = rec.index

    return sessions
