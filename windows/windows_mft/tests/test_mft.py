import io

from _synth import build_ntfs_image, raw_mft_only
from windows_mft.ntfs.mft import Mft, RawMft, open_mft


def _mft():
    img, meta = build_ntfs_image()
    return Mft(io.BytesIO(img)), meta


def test_entries_and_paths():
    mft, meta = _mft()
    ents = {e.name: e for e in mft.iter_entries()}
    assert set(ents) >= {"hello.txt", "secret.txt", "logs", "app.log"}
    assert ents["hello.txt"].in_use
    assert ents["secret.txt"].deleted
    assert ents["logs"].is_directory
    assert mft.full_path(ents["app.log"]) == "logs/app.log"


def test_ads_detected_and_readable():
    mft, meta = _mft()
    hello = next(e for e in mft.iter_entries() if e.name == "hello.txt")
    assert hello.has_ads
    assert hello.ads_names == ["Zone.Identifier"]
    assert mft.read_stream(hello, "Zone.Identifier") == meta["zone"]
    assert mft.read_stream(hello) == meta["hello.txt"]


def test_timestomp_flags():
    mft, meta = _mft()
    stomped = next(e for e in mft.iter_entries() if e.name == "app.log")
    assert stomped.timestomp.any
    assert stomped.timestomp.si_all_equal
    assert stomped.timestomp.si_before_fn
    reasons = stomped.timestomp.reasons()
    assert any("$SI created < $FN created" in r for r in reasons)

    clean = next(e for e in mft.iter_entries() if e.name == "hello.txt")
    assert not clean.timestomp.any


def test_si_fn_times_present():
    mft, meta = _mft()
    e = next(x for x in mft.iter_entries() if x.name == "app.log")
    assert e.si.created == meta["stomp_si"]
    assert e.fn.created == meta["stomp_fn"]


def test_raw_mft_file(tmp_path):
    raw, meta = raw_mft_only()
    p = tmp_path / "$MFT"
    p.write_bytes(raw)
    mft = open_mft(p)
    assert isinstance(mft, RawMft)
    names = {e.name for e in mft.iter_entries()}
    assert "hello.txt" in names and "app.log" in names
    hello = next(e for e in mft.iter_entries() if e.name == "hello.txt")
    assert mft.read_stream(hello) == meta["hello.txt"]  # resident works
