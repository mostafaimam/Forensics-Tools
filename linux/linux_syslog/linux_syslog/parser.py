"""Parse individual syslog lines (RFC 3164 BSD format and RFC 5424)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp",
    "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6",
    "local7",
]
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info",
              "debug"]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec"], 1)}

_PRI_RE = re.compile(r"^<(\d{1,3})>")
# BSD: "Jan  2 03:04:05" optionally followed by a 4-digit year
_BSD_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\s+(\d{4}))?\s+")
# ISO 8601 (rsyslog FileFormat, journald export, RFC 5424 body)
_ISO_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})?\s+")
_TAG_RE = re.compile(r"^([\w./\-]+?)(?:\[(\d+)\])?:\s?")
_5424_RE = re.compile(
    r"^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
    r"(?:-|\[.*?\](?:\s*\[.*?\])*)\s?(.*)$", re.DOTALL)


@dataclass
class LogRecord:
    timestamp: datetime | None
    host: str = ""
    tag: str = ""
    pid: str = ""
    facility: str = ""
    severity: str = ""
    message: str = ""
    raw: str = ""
    source_file: str = ""
    line_no: int = 0
    format: str = "bsd"          # bsd | iso | 5424 | continuation | unparsed


def _pri(pri: int) -> tuple[str, str]:
    fac = pri >> 3
    sev = pri & 7
    return (FACILITIES[fac] if fac < len(FACILITIES) else str(fac),
            SEVERITIES[sev] if sev < len(SEVERITIES) else str(sev))


def _mk_iso_dt(m: re.Match) -> datetime:
    y, mo, d, hh, mm, ss, frac, tz = m.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss), micro)
    if tz in (None, "Z"):
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if tz[0] == "+" else -1
    tz = tz[1:].replace(":", "")
    off = timedelta(hours=int(tz[:2]), minutes=int(tz[2:4]))
    return (dt - sign * off).replace(tzinfo=timezone.utc)


def _bsd_dt(m: re.Match, ref_date: datetime, assume_tz: timezone) -> datetime:
    mon = _MONTHS[m.group(1)]
    day, hh, mm, ss = (int(m.group(i)) for i in (2, 3, 4, 5))
    explicit_year = int(m.group(6)) if m.group(6) else None
    year = explicit_year or ref_date.year
    try:
        dt = datetime(year, mon, day, hh, mm, ss, tzinfo=assume_tz)
    except ValueError:
        dt = datetime(year, mon, min(day, 28), hh, mm, ss, tzinfo=assume_tz)
    if explicit_year is None:
        # lines are written in order but a file whose newest entry is in
        # January can still hold December lines from the year before
        if dt - ref_date > timedelta(days=1):
            dt = dt.replace(year=year - 1)
    return dt.astimezone(timezone.utc)


def parse_line(line: str, *, ref_date: datetime, assume_tz: timezone,
               source_file: str = "", line_no: int = 0) -> LogRecord:
    raw = line.rstrip("\n")
    rec = LogRecord(timestamp=None, raw=raw, source_file=source_file,
                    line_no=line_no, message=raw)
    s = raw
    m = _PRI_RE.match(s)
    if m:
        rec.facility, rec.severity = _pri(int(m.group(1)))
        s = s[m.end():]

    if s[:2] == "1 " or s[:2] == "1\t":
        m5 = _5424_RE.match(s)
        if m5:
            ts, host, app, procid, _msgid, msg = m5.groups()
            rec.format = "5424"
            rec.host = "" if host == "-" else host
            rec.tag = "" if app == "-" else app
            rec.pid = "" if procid == "-" else procid
            rec.message = msg
            mi = _ISO_TS_RE.match(ts + " ")
            if mi:
                rec.timestamp = _mk_iso_dt(mi)
            return rec

    mi = _ISO_TS_RE.match(s)
    if mi:
        rec.timestamp = _mk_iso_dt(mi)
        rec.format = "iso"
        s = s[mi.end():]
        return _finish_bsd_like(rec, s)

    mb = _BSD_TS_RE.match(s)
    if mb:
        rec.timestamp = _bsd_dt(mb, ref_date, assume_tz)
        rec.format = "bsd"
        s = s[mb.end():]
        return _finish_bsd_like(rec, s)

    # not a fresh record - caller treats it as a continuation of the previous
    rec.format = "continuation"
    return rec


def _finish_bsd_like(rec: LogRecord, s: str) -> LogRecord:
    parts = s.split(" ", 1)
    rec.host = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    mt = _TAG_RE.match(rest)
    if mt:
        rec.tag = mt.group(1)
        rec.pid = mt.group(2) or ""
        rec.message = rest[mt.end():]
    else:
        rec.message = rest
    return rec
