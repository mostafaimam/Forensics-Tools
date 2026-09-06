import pytest

from _synth import build_legacy_amcache, build_modern_amcache
from windows_amcache.amcache import parse
from windows_amcache.hive import HiveError


def test_modern_files():
    recs = parse(build_modern_amcache())
    files = [r for r in recs if r.category == "file"]
    assert len(files) == 2
    by_name = {r.as_row()["name"]: r.as_row() for r in files}
    cmd = by_name["cmd.exe"]
    assert cmd["path"] == r"c:\windows\system32\cmd.exe"
    assert cmd["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert cmd["publisher"] == "Microsoft Corporation"
    assert cmd["size"] in ("289792", 289792)
    assert by_name["evil.exe"]["sha1"] == "a" * 40


def test_modern_programs_and_drivers():
    recs = parse(build_modern_amcache())
    progs = [r.as_row() for r in recs if r.category == "program"]
    drivers = [r.as_row() for r in recs if r.category == "driver"]
    assert progs[0]["name"] == "7-Zip 23.01"
    assert progs[0]["publisher"] == "Igor Pavlov"
    assert drivers[0]["sha1"] == "b" * 40
    assert "evil.sys" in drivers[0]["path"]


def test_legacy_format():
    recs = parse(build_legacy_amcache())
    files = [r.as_row() for r in recs if r.category == "file"]
    assert len(files) == 1
    assert files[0]["path"] == r"C:\tools\nc.exe"
    assert files[0]["name"] == "Netcat"
    assert files[0]["sha1"] == "c" * 40


def test_not_a_hive():
    with pytest.raises(HiveError):
        parse(b"PK\x03\x04 definitely not a registry hive here padding....")
