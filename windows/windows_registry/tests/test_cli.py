import csv
import json

from _synth import build_sample_hive
from windows_registry.cli import main


def _hive(tmp_path):
    p = tmp_path / "HIVE.dat"
    p.write_bytes(build_sample_hive())
    return p


def test_dump_csv(tmp_path):
    p = _hive(tmp_path)
    out = tmp_path / "d.csv"
    rc = main(["dump", str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    paths = {r["key_path"] for r in rows}
    assert "ROOT\\TestKey" in paths
    note = next(r for r in rows if r["value_name"] == "Note")
    assert note["value_data"] == "hello world"
    assert note["value_type"] == "REG_SZ"


def test_dump_deleted(tmp_path):
    p = _hive(tmp_path)
    out = tmp_path / "r.csv"
    main(["dump", str(p), "--deleted", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert any(r["deleted"] == "yes" and "DeletedSecretKey" in r["key_path"]
               for r in rows)


def test_key_command(tmp_path, capsys):
    p = _hive(tmp_path)
    rc = main(["key", str(p), "Software\\Microsoft\\Windows\\CurrentVersion\\Run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OneDrive" in out and "OneDrive.exe" in out


def test_search(tmp_path, capsys):
    p = _hive(tmp_path)
    rc = main(["search", str(p), "onedrive", "--value-data", "-q"])
    assert rc == 0
    rc = main(["search", str(p), "nonexistent-xyz", "-q"])
    assert rc == 1


def test_plugin_run_keys(tmp_path):
    p = _hive(tmp_path)
    out = tmp_path / "p.csv"
    rc = main(["plugin", str(p), "--plugin", "run-keys", "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader((tmp_path / "p_run-keys.csv").open(encoding="utf-8-sig")))
    assert rows and rows[0]["name"] == "OneDrive"
    assert "OneDrive.exe" in rows[0]["command"]


def test_list_plugins(capsys):
    assert main(["--list-plugins"]) == 0
    assert "userassist" in capsys.readouterr().out


def test_missing_hive(tmp_path):
    assert main(["dump", str(tmp_path / "nope.dat")]) == 2
