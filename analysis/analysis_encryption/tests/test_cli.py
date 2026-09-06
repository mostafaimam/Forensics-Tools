import csv
import os

from analysis_encryption.cli import main


def _tree(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    (d / "readme.txt").write_bytes(b"hello world\n" * 50)
    (d / "secret.age").write_bytes(b"age-encryption.org/v1\n-> scrypt abc\n")
    (d / "vault.kdbx").write_bytes(b"\x03\xd9\xa2\x9a" + os.urandom(300))
    (d / "blob.tc").write_bytes(os.urandom(1 << 20))
    return d


def test_scan_csv_and_exit_code(tmp_path):
    out = tmp_path / "e.csv"
    rc = main(["scan", str(_tree(tmp_path)), "--csv", str(out), "-q"])
    assert rc == 1                       # encrypted files present
    rows = {os.path.basename(r["path"]): r
            for r in csv.DictReader(out.open(encoding="utf-8-sig"))}
    assert rows["secret.age"]["verdict"] == "encrypted"
    assert rows["vault.kdbx"]["scheme"] == "keepass"
    assert rows["blob.tc"]["verdict"] == "high-entropy"
    assert "readme.txt" not in rows      # clear files hidden by default


def test_include_clear(tmp_path):
    out = tmp_path / "a.json"
    main(["scan", str(_tree(tmp_path)), "--include-clear", "--json", str(out),
          "-q"])
    import json
    names = {os.path.basename(r["path"]) for r in json.loads(out.read_text())}
    assert "readme.txt" in names


def test_all_clear_exit_zero(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "a.txt").write_bytes(b"plain\n" * 100)
    assert main(["scan", str(d), "-q"]) == 0


def test_missing(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2
