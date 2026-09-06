import json

from _synth import disk_bytes, md5
from acquisition_image.cli import main


def test_acquire_ewf_end_to_end(tmp_path, capsys):
    data = disk_bytes(1024)
    src = tmp_path / "src.dd"
    src.write_bytes(data)
    out = tmp_path / "case.E01"
    rc = main(["acquire", str(src), str(out), "--format", "ewf", "--verify",
               "--case", "2026-014", "--examiner", "A. Analyst", "-q"])
    assert rc == 0
    assert out.exists()
    log = (tmp_path / "case.E01.txt").read_text()
    assert "2026-014" in log and "A. Analyst" in log
    assert md5(data) in log
    assert "Verification (ok)" in log
    man = json.loads((tmp_path / "case.E01.json").read_text())
    assert man["hashes"]["md5"] == md5(data)
    assert man["verified"] == "ok"
    assert (tmp_path / "case.E01.html").exists()


def test_acquire_split_raw(tmp_path):
    data = disk_bytes(600)
    src = tmp_path / "s.dd"
    src.write_bytes(data)
    out = tmp_path / "img.raw"
    rc = main(["acquire", str(src), str(out), "--split", "80k", "-q"])
    assert rc == 0
    segs = sorted(tmp_path.glob("img.raw.*"))
    segs = [s for s in segs if s.suffix[1:].isdigit()]
    assert len(segs) >= 3
    assert b"".join(s.read_bytes() for s in segs) == data


def test_verify_command(tmp_path, capsys):
    data = disk_bytes(400)
    src = tmp_path / "s.dd"
    src.write_bytes(data)
    out = tmp_path / "o.raw"
    main(["acquire", str(src), str(out), "-q"])
    rc = main(["verify", str(out), "--md5", md5(data)])
    assert rc == 0
    assert "MATCH" in capsys.readouterr().out


def test_hash_command(tmp_path, capsys):
    data = disk_bytes(200)
    src = tmp_path / "s.dd"
    src.write_bytes(data)
    rc = main(["hash", str(src)])
    assert rc == 0
    assert md5(data) in capsys.readouterr().out


def test_missing_source(tmp_path):
    assert main(["acquire", str(tmp_path / "nope"), str(tmp_path / "o.raw"),
                 "-q"]) == 2
