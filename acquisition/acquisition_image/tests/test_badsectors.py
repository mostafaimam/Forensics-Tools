import hashlib
from unittest import mock

from _synth import FlakySource, disk_bytes
from acquisition_image import imager


def test_bad_sectors_zero_filled_and_logged(tmp_path):
    data = disk_bytes(64)
    flaky = FlakySource(data, bad_sectors=(3, 4, 10))

    with mock.patch.object(imager, "Source", return_value=flaky):
        res = imager.acquire("whatever", str(tmp_path / "o.raw"), "raw")

    expected = bytearray(data)
    for s in (3, 4, 10):
        expected[s * 512:(s + 1) * 512] = b"\x00" * 512
    written = (tmp_path / "o.raw").read_bytes()
    assert written == bytes(expected)
    assert res.hashes["md5"] == hashlib.md5(bytes(expected)).hexdigest()

    # sectors 3-4 coalesce into one range, sector 10 its own
    offs = {(b["offset"], b["length"]) for b in res.bad_ranges}
    assert (3 * 512, 2 * 512) in offs
    assert (10 * 512, 512) in offs
    assert not res.ok            # bad regions -> needs review
