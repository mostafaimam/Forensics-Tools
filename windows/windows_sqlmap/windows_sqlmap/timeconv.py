"""Convert a raw timestamp value per a map's declared time_format."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def convert(value, fmt: str) -> str:
    if value is None or value == "":
        return ""
    try:
        if fmt == "unix":
            return (_EPOCH + timedelta(seconds=float(value))).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        if fmt == "unix_ms":
            return (_EPOCH + timedelta(milliseconds=float(value))).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        if fmt == "unix_us":
            return (_EPOCH + timedelta(microseconds=float(value))).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        if fmt == "webkit":
            return (_WEBKIT_EPOCH + timedelta(microseconds=float(value))
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
        if fmt == "filetime":
            v = int(value)
            return (_FT_EPOCH + timedelta(microseconds=v // 10)).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        if fmt == "iso":
            return str(value)
    except (ValueError, OverflowError, OSError, TypeError):
        return str(value)
    return str(value)
