import csv
import json

from _synth import build_legacy_amcache, build_modern_amcache
from windows_amcache.cli import main


def test_csv(tmp_path):
    (tmp_path / "Amcache.hve").write_bytes(build_modern_amcache())
    out = tmp_path / "a.csv"
    rc = main([str(tmp_path / "Amcache.hve"), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    cats = {r["category"] for r in rows}
    assert cats == {"file", "program", "driver"}
    cmd = next(r for r in rows if r["name"] == "cmd.exe")
    assert len(cmd["sha1"]) == 40
    assert cmd["key_last_written_utc"].endswith("Z")


def test_category_and_grep(tmp_path):
    (tmp_path / "Amcache.hve").write_bytes(build_modern_amcache())
    out = tmp_path / "f.csv"
    main([str(tmp_path / "Amcache.hve"), "--category", "file",
          "--grep", r"\\temp\\", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert [r["name"] for r in rows] == ["evil.exe"]


def test_with_sha1_filter(tmp_path):
    (tmp_path / "Amcache.hve").write_bytes(build_modern_amcache())
    out = tmp_path / "s.json"
    main([str(tmp_path / "Amcache.hve"), "--with-sha1", "--json", str(out), "-q"])
    data = json.loads(out.read_text())
    assert data and all(d["sha1"] for d in data)


def test_legacy_cli(tmp_path):
    (tmp_path / "Amcache.hve").write_bytes(build_legacy_amcache())
    out = tmp_path / "l.csv"
    rc = main([str(tmp_path / "Amcache.hve"), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows[0]["path"] == r"C:\tools\nc.exe"


def test_missing(tmp_path):
    assert main([str(tmp_path / "nope.hve")]) == 2
