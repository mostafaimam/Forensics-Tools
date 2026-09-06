import hashlib

import pytest

from _synth import disk_bytes, md5
from acquisition_image.ewf_read import EWFReader
from acquisition_image.imager import acquire, verify


@pytest.fixture
def src(tmp_path):
    data = disk_bytes(2048)
    p = tmp_path / "src.dd"
    p.write_bytes(data)
    return p, data


def test_raw_acquire_and_verify(src, tmp_path):
    p, data = src
    out = tmp_path / "out.raw"
    res = acquire(str(p), str(out), "raw")
    assert res.bytes_read == len(data)
    assert res.hashes["md5"] == md5(data)
    assert res.hashes["sha256"] == hashlib.sha256(data).hexdigest()
    assert out.read_bytes() == data
    v = verify(str(out), "raw", expected=res.hashes)
    assert v["match"] and v["sha1"] == res.hashes["sha1"]


def test_split_raw_reassembles(src, tmp_path):
    p, data = src
    out = tmp_path / "img.raw"
    res = acquire(str(p), str(out), "split", split_size=100_000)
    assert len(res.segments) == 11
    assert res.segments[0].endswith(".001")
    joined = b"".join(open(s, "rb").read() for s in res.segments)
    assert joined == data
    assert verify(str(out), "raw", expected=res.hashes)["match"]


def test_ewf_roundtrip_bytes_and_digest(src, tmp_path):
    p, data = src
    out = tmp_path / "ev.E01"
    res = acquire(str(p), str(out), "ewf", compression="fast")
    r = EWFReader(res.segments[0])
    assert r.size == len(data)
    assert b"".join(r.chunks()) == data
    assert r.stored_md5 == md5(data)
    assert r.stored_sha1 == res.hashes["sha1"]
    r.close()
    v = verify(res.segments[0], "ewf")
    assert v["match"] and v["md5"] == md5(data)


def test_ewf_compression_none(src, tmp_path):
    p, data = src
    out = tmp_path / "n.E01"
    res = acquire(str(p), str(out), "ewf", compression="none")
    assert b"".join(EWFReader(res.segments[0]).chunks()) == data


def test_ewf_multi_segment(src, tmp_path):
    p, data = src
    out = tmp_path / "m.E01"
    res = acquire(str(p), str(out), "ewf", segment_size=200_000,
                  compression="none")
    assert len(res.segments) > 1
    assert res.segments[1].endswith(".E02")
    assert b"".join(EWFReader(res.segments[0]).chunks()) == data
    assert verify(res.segments[0], "ewf")["match"]


def test_non_sector_aligned_source_is_padded(tmp_path):
    data = disk_bytes(4) + b"\xaa" * 300          # 2048 + 300 bytes
    p = tmp_path / "odd.dd"
    p.write_bytes(data)
    res = acquire(str(p), str(tmp_path / "o.E01"), "ewf")
    assert res.padded == 512 - 300
    padded = data + b"\x00" * res.padded
    assert res.hashes["md5"] == hashlib.md5(padded).hexdigest()
    assert verify(res.segments[0], "ewf")["match"]


def test_offset_and_length(src, tmp_path):
    p, data = src
    out = tmp_path / "slice.raw"
    res = acquire(str(p), str(out), "raw", offset=512, length=1024)
    assert out.read_bytes() == data[512:1536]
    assert res.hashes["md5"] == md5(data[512:1536])
