import pytest

from _synth import h
from analysis_kff.store import KFFStore


def test_import_and_classify(tmp_path):
    s = KFFStore(tmp_path / "kff.db")
    good = s.create_set("nsrl", "known-good")
    s.import_records(good, iter([h(b"windows-dll"), h(b"benign")]))
    bad = s.create_set("iocs", "known-bad")
    s.import_records(bad, iter([h(b"malware")]))

    assert s.classify(h(b"windows-dll"))["status"] == "known-good"
    assert s.classify(h(b"malware"))["status"] == "known-bad"
    assert s.classify(h(b"never-seen"))["status"] == "unknown"


def test_bad_beats_good(tmp_path):
    s = KFFStore(tmp_path / "kff.db")
    g = s.create_set("g", "known-good")
    b = s.create_set("b", "known-bad")
    rec = h(b"dual-use")
    s.import_records(g, iter([rec]))
    s.import_records(b, iter([rec]))
    res = s.classify(rec)
    assert res["status"] == "known-bad" and res["set"] == "b"


def test_partial_hash_lookup(tmp_path):
    s = KFFStore(tmp_path / "kff.db")
    sid = s.create_set("x", "notable")
    rec = h(b"thing")
    s.import_records(sid, iter([rec]))
    # only the sha256 is known to us at query time
    assert s.classify({"sha256": rec["sha256"]})["status"] == "notable"
    assert s.classify({"md5": "0" * 32})["status"] == "unknown"


def test_remove_and_stats(tmp_path):
    s = KFFStore(tmp_path / "kff.db")
    sid = s.create_set("temp", "known-good")
    s.import_records(sid, iter([h(b"a"), h(b"b")]))
    assert s.stats()["hashes"] == 6          # 2 files x 3 algos
    assert s.remove_set("temp")
    assert s.stats()["hashes"] == 0
    assert not s.remove_set("temp")


def test_empty_source_rejected(tmp_path):
    s = KFFStore(tmp_path / "kff.db")
    sid = s.create_set("e", "known-good")
    with pytest.raises(ValueError):
        s.import_records(sid, iter([]))
