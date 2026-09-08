import csv

from _synth import lime_with
from memory_strings.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d


def test_scan_classified_csv(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(lime_with({
        0x1000: b"\x00http://c2.example/gate.php\x00",
        0x2000: b"\x00HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00",
        0x3000: b"\x00powershell.exe -enc AAAAAAAAAAAAAAAAAAAAAAAA\x00",
    }))
    out = tmp_path / "s.csv"
    rc = main(["scan", str(p), "--classified", "--csv", str(out)])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    cats = {r["category"] for r in rows}
    assert {"url", "registry", "powershell"} <= cats
    assert all(r["phys"].startswith("0x") for r in rows)


def test_scan_grep(tmp_path, capsys):
    p = tmp_path / "m.lime"
    p.write_bytes(lime_with({0x1000: b"\x00the Administrator account is here\x00"}))
    rc = main(["scan", str(p), "--grep", "administrator"])
    assert rc == 0
    assert "Administrator" in capsys.readouterr().out


def test_categories(capsys):
    assert main(["categories"]) == 0
    assert "url" in capsys.readouterr().out


def test_missing(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2
