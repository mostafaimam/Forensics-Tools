"""Lenient timestamp parsing -> aware UTC datetime.

Accepts ISO-8601 (with ``T`` or space, optional fractional seconds, optional
``Z`` / numeric offset), a few common log formats, and - with ``allow_epoch`` -
Unix seconds / milliseconds.  A value with no timezone is assumed to be UTC.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_ISO_CLEAN = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%b %d %H:%M:%S %Y",
    "%Y-%m-%d",
)


class TimeParseError(ValueError):
    pass


def to_utc(value, *, allow_epoch: bool = False,
           assume_year: int | None = None) -> datetime:
    if isinstance(value, datetime):
        return _as_utc(value)
    if value is None:
        raise TimeParseError("empty timestamp")

    s = str(value).strip()
    if not s:
        raise TimeParseError("empty timestamp")

    if allow_epoch:
        num = _maybe_number(s)
        if num is not None:
            if num > 1e12:          # milliseconds
                num /= 1000.0
            if num > 1e10:          # 100-ns or micro - treat as ms already handled
                num /= 1000.0
            return datetime.fromtimestamp(num, tz=timezone.utc)

    iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        return _as_utc(datetime.fromisoformat(iso))
    except ValueError:
        pass

    # normalise "YYYY-MM-DD HH:MM:SS[.ffffff]" then retry fromisoformat
    m = _ISO_CLEAN.match(s)
    if m:
        try:
            return _as_utc(datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}"))
        except ValueError:
            pass

    for fmt in _FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if "%Y" not in fmt and assume_year:
                dt = dt.replace(year=assume_year)
            return _as_utc(dt)
        except ValueError:
            continue

    raise TimeParseError(f"unrecognised timestamp: {value!r}")


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _maybe_number(s: str):
    try:
        return float(s)
    except ValueError:
        return None


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
