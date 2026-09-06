import json

from _synth import make_e01, make_gpt_disk, make_mbr_disk, make_vhd_dynamic
from mounting_image.cli import main


def test_info_text_and_hash(tmp_path, capsys):
    raw = make_mbr_disk()
    p = tmp_path / "d.E01"
    p.write_bytes(make_e01(raw))
    rc = main(["info", str(p), "--hash", "sha256"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "format        : ewf" in out
    assert "NTFS/exFAT" in out
    import hashlib
    assert hashlib.sha256(raw).hexdigest() in out


def test_partitions_json(tmp_path):
    p = tmp_path / "d.raw"
    p.write_bytes(make_gpt_disk())
    out = tmp_path / "parts.json"
    rc = main(["partitions", str(p), "--json", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["scheme"] == "gpt"
    assert data["partitions"][1]["name"] == "ESP"


def test_convert_whole_disk(tmp_path):
    raw = make_vhd_dynamic(make_mbr_disk())
    p = tmp_path / "d.vhd"
    p.write_bytes(raw)
    out = tmp_path / "d.raw"
    rc = main(["convert", str(p), str(out)])
    assert rc == 0
    assert out.read_bytes() == make_mbr_disk()


def test_extract_partition(tmp_path):
    disk = make_mbr_disk()
    p = tmp_path / "d.raw"
    p.write_bytes(disk)
    out = tmp_path / "p1.raw"
    rc = main(["extract", str(p), "--partition", "1", "--out", str(out)])
    assert rc == 0
    body = out.read_bytes()
    assert len(body) == 4096 * 512
    assert body[:5] == b"PART1"


def test_cat_range(tmp_path, capsysbinary):
    disk = make_mbr_disk()
    p = tmp_path / "d.raw"
    p.write_bytes(disk)
    rc = main(["cat", str(p), "--offset", str(2048 * 512), "--size", "8"])
    assert rc == 0
    assert capsysbinary.readouterr().out[:5] == b"PART1"


def test_info_html(tmp_path):
    p = tmp_path / "d.raw"
    p.write_bytes(make_gpt_disk())
    html = tmp_path / "r.html"
    main(["info", str(p), "--html", str(html)])
    t = html.read_text()
    assert "<table" in t and "EFI System" in t


def test_missing_image(tmp_path):
    assert main(["info", str(tmp_path / "nope.raw")]) == 2


def test_bad_partition(tmp_path, capsys):
    p = tmp_path / "d.raw"
    p.write_bytes(make_mbr_disk())
    rc = main(["extract", str(p), "--partition", "9", "--out",
               str(tmp_path / "x")])
    assert rc == 2
    assert "no partition 9" in capsys.readouterr().err
