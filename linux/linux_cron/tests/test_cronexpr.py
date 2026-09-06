import pytest

from linux_cron.cronexpr import CronError, parse


def test_shortcuts():
    assert parse("@reboot").reboot is True
    d = parse("@daily")
    assert d.minute == {0} and d.hour == {0} and d.dom is None


def test_step_and_range():
    s = parse("*/15 9-17 * * mon-fri")
    assert s.minute == {0, 15, 30, 45}
    assert s.hour == {9, 10, 11, 12, 13, 14, 15, 16, 17}
    assert s.dow == {1, 2, 3, 4, 5}
    assert s.dow_restricted and not s.dom_restricted


def test_names_and_sunday_seven():
    s = parse("0 0 * jan,dec 7")
    assert s.month == {1, 12}
    assert s.dow == {0}


def test_list_and_single():
    s = parse("5,35 * * * *")
    assert s.minute == {5, 35}


def test_describe_reads_cleanly():
    assert "every 15 minutes" in parse("*/15 * * * *").describe()
    assert parse("@reboot").describe().startswith("at boot")
    txt = parse("30 2 * * 0").describe()
    assert "02:30" in txt and "Sunday" in txt


def test_bad_expressions():
    with pytest.raises(CronError):
        parse("* * *")
    with pytest.raises(CronError):
        parse("bogus * * * *")
    with pytest.raises(CronError):
        parse("*/0 * * * *")
