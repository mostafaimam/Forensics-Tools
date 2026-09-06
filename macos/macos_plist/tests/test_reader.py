from datetime import datetime, timezone

from _synth import bplist, keyed_archive_dock, sample_prefs, xmlplist
from macos_plist.nskeyedarchiver import is_keyed_archive, unwrap
from macos_plist.reader import (
    cocoa_to_utc,
    detect_format,
    load_bytes,
)


def test_detect_format():
    assert detect_format(bplist({"a": 1})) == "binary"
    assert detect_format(xmlplist({"a": 1})) == "xml"
    assert detect_format(b"just some text") == "unknown"


def test_load_binary_and_xml():
    for data in (bplist(sample_prefs()), xmlplist(sample_prefs())):
        lp = load_bytes(data, "prefs.plist")
        assert not lp.parse_error
        assert lp.value["AppleLanguages"] == ["en-GB", "fr"]
        assert lp.value["com.apple.something"]["Count"] == 3
        assert isinstance(lp.value["LastRun"], datetime)


def test_corrupt_plist_reports_error():
    lp = load_bytes(b"bplist00\xff\xff\xff garbage", "bad.plist")
    assert lp.parse_error
    assert lp.value is None


def test_keyed_archive_detected_and_unwrapped():
    lp = load_bytes(keyed_archive_dock(), "dock.plist")
    assert lp.is_keyed_archive
    assert is_keyed_archive(lp.value)
    root = unwrap(lp.value)
    assert root["name"] == "Safari"
    assert isinstance(root["added"], datetime)
    assert root["added"].year == 2023        # cocoa 707313600 -> 2023-06-01


def test_cocoa_to_utc():
    dt = cocoa_to_utc(0)
    assert dt == datetime(2001, 1, 1, tzinfo=timezone.utc)
