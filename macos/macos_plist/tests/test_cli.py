import csv
import json

from _synth import bplist, keyed_archive_dock, sample_prefs, xmlplist
from macos_plist.cli import main


def test_csv_flatten(tmp_path):
    (tmp_path / "prefs.plist").write_bytes(bplist(sample_prefs()))
    out = tmp_path / "o.csv"
    rc = main([str(tmp_path / "prefs.plist"), "--csv", str(out), "-q"])
    assert rc == 0
    rows = {r["key_path"]: r["value"]
            for r in csv.DictReader(out.open(encoding="utf-8-sig"))}
    assert rows["AppleLanguages[0]"] == "en-GB"
    assert rows["com.apple.something.Count"] == "3"
    assert rows["LastRun"].endswith("Z")
    assert rows["Token"].startswith("base64:")


def test_json_unwraps_keyed_archive(tmp_path):
    (tmp_path / "dock.plist").write_bytes(keyed_archive_dock())
    out = tmp_path / "d.json"
    rc = main([str(tmp_path / "dock.plist"), "--json", str(out), "-q"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data[0]["keyed_archive"] is True
    assert data[0]["value"]["name"] == "Safari"
    assert data[0]["value"]["added"].startswith("2023-06-01")


def test_no_unwrap_keeps_raw(tmp_path):
    (tmp_path / "dock.plist").write_bytes(keyed_archive_dock())
    out = tmp_path / "raw.json"
    main([str(tmp_path / "dock.plist"), "--no-unwrap", "--json", str(out), "-q"])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "$objects" in data[0]["value"]


def test_key_extraction(tmp_path, capsys):
    (tmp_path / "p.plist").write_bytes(xmlplist(sample_prefs()))
    rc = main([str(tmp_path / "p.plist"), "--key", "com.apple.something.Enabled"])
    assert rc == 0
    assert "true" in capsys.readouterr().out


def test_directory_scan(tmp_path):
    (tmp_path / "a.plist").write_bytes(bplist({"x": 1}))
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.plist").write_bytes(bplist({"y": 2}))
    out = tmp_path / "all.csv"
    rc = main([str(tmp_path), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert {r["key_path"] for r in rows} == {"x", "y"}


def test_all_corrupt_returns_1(tmp_path):
    (tmp_path / "bad.plist").write_bytes(b"bplist00\x00\x00 nope")
    assert main([str(tmp_path / "bad.plist"), "-q"]) == 1
