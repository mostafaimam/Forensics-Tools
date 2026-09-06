import csv
import hashlib

from _synth import build_image
from recovery_carve.cli import main


def test_carve_all_from_image(tmp_path):
    img = tmp_path / "disk.dd"
    layout = build_image(img)
    out = tmp_path / "out"

    rc = main([str(img), "-o", str(out), "--hash", "md5,sha1", "-q"])
    assert rc == 0

    rows = list(csv.DictReader((out / "recovery_carve_manifest.csv").open(encoding="utf-8-sig")))
    by_type = {r["type"]: r for r in rows}
    for kind in ("png", "jpg", "bmp", "gif", "sqlite", "zip"):
        assert kind in by_type, f"missing {kind}"
        r = by_type[kind]
        exp_off, exp_len, exp_data = layout[kind]
        assert int(r["offset"]) == exp_off
        assert int(r["length_bytes"]) == exp_len
        assert r["md5"] == hashlib.md5(exp_data).hexdigest()
        # carved file on disk matches byte-for-byte
        assert Path_read(r["output_path"]) == exp_data
        assert r["confidence"] in ("structure", "footer")


def Path_read(p):
    from pathlib import Path
    return Path(p).read_bytes()


def test_manifest_only_writes_no_files(tmp_path):
    img = tmp_path / "disk.dd"
    build_image(img)
    out = tmp_path / "out"
    rc = main([str(img), "-o", str(out), "--manifest-only", "-q"])
    assert rc == 0
    assert not (out / "carved").exists()
    assert (out / "recovery_carve_manifest.csv").exists()


def test_type_filter(tmp_path):
    img = tmp_path / "disk.dd"
    build_image(img)
    out = tmp_path / "out"
    rc = main([str(img), "-o", str(out), "--types", "png,bmp", "-q"])
    assert rc == 0
    rows = list(csv.DictReader((out / "recovery_carve_manifest.csv").open(encoding="utf-8-sig")))
    assert {r["type"] for r in rows} <= {"png", "bmp"}
    assert {r["type"] for r in rows} == {"png", "bmp"}


def test_list_signatures(capsys):
    rc = main(["--list-signatures"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "sqlite" in out and "jpg" in out


def test_missing_args(capsys):
    assert main(["nonexist.dd"]) == 2
