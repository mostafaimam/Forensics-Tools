import csv
import json

from _synth import build_ntfs_image, build_usn_journal
from windows_mft.cli import main


def _img(tmp_path):
    img, meta = build_ntfs_image()
    p = tmp_path / "vol.raw"
    p.write_bytes(img)
    return p, meta


def test_mft_csv(tmp_path):
    p, _ = _img(tmp_path)
    out = tmp_path / "mft.csv"
    rc = main(["mft", str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = {r["path"]: r for r in csv.DictReader(out.open(encoding="utf-8-sig"))}
    assert rows["hello.txt"]["has_ads"] == "yes"
    assert rows["hello.txt"]["ads_names"] == "Zone.Identifier"
    assert rows["secret.txt"]["state"] == "deleted"
    assert rows["logs/app.log"]["timestomp"] == "yes"
    assert rows["hello.txt"]["si_modified_utc"].endswith("Z")


def test_mft_timestomped_only(tmp_path):
    p, _ = _img(tmp_path)
    out = tmp_path / "s.csv"
    main(["mft", str(p), "--csv", str(out), "--timestomped-only", "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["timestomp"] == "yes" for r in rows)
    assert any(r["name"] == "app.log" for r in rows)


def test_mft_bodyfile(tmp_path):
    p, _ = _img(tmp_path)
    out = tmp_path / "bodyfile"
    main(["mft", str(p), "--bodyfile", str(out), "-q"])
    text = out.read_text()
    assert "hello.txt" in text
    assert text.count("|") >= 10  # bodyfile format has 10 pipes per line


def test_cat_ads(tmp_path, capsysbinary):
    p, meta = _img(tmp_path)
    # entry number of hello.txt
    import io

    from windows_mft.ntfs.mft import Mft
    m = Mft(io.BytesIO(p.read_bytes()))
    n = next(e.number for e in m.iter_entries() if e.name == "hello.txt")
    rc = main(["cat", str(p), "--entry", str(n), "--stream", "Zone.Identifier"])
    assert rc == 0
    assert capsysbinary.readouterr().out == meta["zone"]


def test_usn_cli(tmp_path):
    blob, _ = build_usn_journal()
    j = tmp_path / "J"
    j.write_bytes(blob)
    out = tmp_path / "usn.csv"
    rc = main(["usn", str(j), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 4
    assert any("FILE_DELETE" in r["reasons"] for r in rows)


def test_usn_reason_filter(tmp_path):
    blob, _ = build_usn_journal()
    j = tmp_path / "J"
    j.write_bytes(blob)
    out = tmp_path / "u.json"
    main(["usn", str(j), "--json", str(out), "--reason", "FILE_DELETE", "-q"])
    data = json.loads(out.read_text())
    assert len(data) == 1 and data[0]["name"] == "evil.exe"


def test_not_ntfs(tmp_path):
    (tmp_path / "x").write_bytes(b"\x00" * 4096)
    assert main(["mft", str(tmp_path / "x")]) == 2
