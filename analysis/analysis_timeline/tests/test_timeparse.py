from datetime import datetime, timezone

import pytest

from analysis_timeline.timeparse import TimeParseError, to_utc


@pytest.mark.parametrize("value", [
    "2024-03-01T12:30:00.000000Z",
    "2024-03-01T12:30:00Z",
    "2024-03-01 12:30:00",
    "2024-03-01T12:30:00+00:00",
    "2024/03/01 12:30:00",
])
def test_iso_variants(value):
    dt = to_utc(value)
    assert dt == datetime(2024, 3, 1, 12, 30, tzinfo=timezone.utc)


def test_offset_is_converted_to_utc():
    assert to_utc("2024-03-01T14:30:00+02:00") == datetime(
        2024, 3, 1, 12, 30, tzinfo=timezone.utc)


def test_naive_assumed_utc():
    assert to_utc("2024-03-01T12:30:00").tzinfo == timezone.utc


def test_epoch_seconds_and_ms():
    assert to_utc("1709296200", allow_epoch=True) == datetime(
        2024, 3, 1, 12, 30, tzinfo=timezone.utc)
    assert to_utc("1709296200000", allow_epoch=True) == datetime(
        2024, 3, 1, 12, 30, tzinfo=timezone.utc)


def test_epoch_not_allowed_by_default():
    with pytest.raises(TimeParseError):
        to_utc("1709296200")


def test_bad_value():
    with pytest.raises(TimeParseError):
        to_utc("not a date")
