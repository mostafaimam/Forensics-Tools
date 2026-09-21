"""Timestamp conversions for the browser history stores."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_EPOCH_1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)
_EPOCH_2001 = datetime(2001, 1, 1, tzinfo=timezone.utc)

_LO = datetime(1995, 1, 1, tzinfo=timezone.utc)
_HI = datetime(2100, 1, 1, tzinfo=timezone.utc)


def _clamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if _LO <= dt <= _HI else ""


def chrome(value) -> str:
    """Microseconds since 1601-01-01 UTC (Chromium ``last_visit_time`` etc.)."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return ""
    if v == 0:
        return ""
    try:
        return _clamp(_EPOCH_1601 + timedelta(microseconds=v))
    except (OverflowError, OSError):
        return ""


def webkit_us(value) -> str:
    """Microseconds since 1970 (Firefox ``visit_date``, Chrome download times
    in newer builds are still 1601 - handled by :func:`chrome`)."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return ""
    if v == 0:
        return ""
    try:
        return _clamp(_EPOCH_1970 + timedelta(microseconds=v))
    except (OverflowError, OSError):
        return ""


def cocoa(value) -> str:
    """Seconds (float) since 2001-01-01 UTC (Safari ``visit_time``)."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v == 0:
        return ""
    try:
        return _clamp(_EPOCH_2001 + timedelta(seconds=v))
    except (OverflowError, OSError):
        return ""


def unix_s(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v == 0:
        return ""
    try:
        return _clamp(_EPOCH_1970 + timedelta(seconds=v))
    except (OverflowError, OSError):
        return ""
