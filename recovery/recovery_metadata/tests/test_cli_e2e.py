import csv

from _synth import build_ntfs_image
from recovery_metadata.cli import main


def _image(tmp_path):
    img, expected = build_ntfs_image()
    p = tmp_path / "vol.raw"
    p.write_bytes(img)
    return p, expected


def test_list_csv(tmp_path, capsys):
    p, _ = _image(tmp_path)
    out = tmp_path / "mft.csv"
    rc = main(["list", str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = {r["path"]: r for r in csv.DictReader(out.open(encoding="utf-8-sig"))}
    assert rows["hello.txt"]["sequence_state"] == "allocated"
    assert rows["secret.txt"]["sequence_state"] == "deleted"
    assert rows["hello.txt"]["si_modified_utc"].endswith("Z")


def test_list_deleted_only(tmp_path):
    p, _ = _image(tmp_path)
    out = tmp_path / "d.csv"
    main(["list", str(p), "--csv", str(out), "--deleted-only", "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["sequence_state"] == "deleted" for r in rows)
    assert any(r["path"] == "secret.txt" for r in rows)


def test_extract_tree(tmp_path):
    p, expected = _image(tmp_path)
    out = tmp_path / "rec"
    rc = main(["extract", str(p), "-o", str(out), "--hash", "md5,sha1"])
    assert rc == 0
    assert (out / "allocated" / "hello.txt").read_bytes() == expected["hello.txt"]
    assert (out / "deleted" / "secret.txt").read_bytes() == expected["secret.txt"]
    man = list(csv.DictReader(
        (out / "recovery_metadata_extracted.csv").open(encoding="utf-8-sig")))
    assert {m["state"] for m in man} == {"allocated", "deleted"}
    assert all(m["sha1"] for m in man)


def test_cat_entry_to_stdout(tmp_path, capsysbinary):
    import io

    from recovery_metadata.ntfs.volume import NtfsVolume

    p, expected = _image(tmp_path)
    vol = NtfsVolume(io.BytesIO(p.read_bytes()))
    num = next(e.number for e in vol.iter_entries() if e.name == "secret.txt")
    rc = main(["cat", str(p), "--entry", str(num)])
    assert rc == 0
    assert capsysbinary.readouterr().out == expected["secret.txt"]


def test_not_ntfs(tmp_path):
    (tmp_path / "junk.raw").write_bytes(b"\x00" * 4096)
    assert main(["list", str(tmp_path / "junk.raw")]) == 2
