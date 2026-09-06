from _synth import disk_bytes, md5
from acquisition_image.imager import acquire, verify


def test_verify_raw_detects_tampering(tmp_path):
    data = disk_bytes(1024)
    p = tmp_path / "s.dd"
    p.write_bytes(data)
    out = tmp_path / "o.raw"
    res = acquire(str(p), str(out), "raw")
    assert verify(str(out), "raw", expected=res.hashes)["match"]

    b = bytearray(out.read_bytes())
    b[5000] ^= 0xFF
    out.write_bytes(b)
    assert not verify(str(out), "raw", expected=res.hashes)["match"]


def test_verify_ewf_against_embedded_digest(tmp_path):
    data = disk_bytes(1024)
    p = tmp_path / "s.dd"
    p.write_bytes(data)
    res = acquire(str(p), str(tmp_path / "e.E01"), "ewf")
    v = verify(res.segments[0], "ewf")
    assert v["compared_against"] == "embedded digest"
    assert v["match"] and v["md5"] == md5(data)


def test_verify_explicit_hash(tmp_path):
    data = disk_bytes(512)
    p = tmp_path / "s.dd"
    p.write_bytes(data)
    out = tmp_path / "o.raw"
    acquire(str(p), str(out), "raw")
    assert verify(str(out), "raw", expected={"md5": md5(data)})["match"]
    assert not verify(str(out), "raw", expected={"md5": "0" * 32})["match"]
