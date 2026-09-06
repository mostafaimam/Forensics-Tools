import csv
import json
from datetime import datetime, timezone

from _synth import system_hive_with_shimcache, win7_blob, win10_blob
from windows_shimcache.cli import main

D = datetime(2024, 4, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_csv_from_hive(tmp_path):
    blob = win10_blob([(r"C:\Windows\System32\svchost.exe", D),
                       (r"C:\Users\x\Downloads\setup.exe", D)])
    (tmp_path / "SYSTEM").write_bytes(system_hive_with_shimcache(blob))
    out = tmp_path / "s.csv"
    rc = main([str(tmp_path / "SYSTEM"), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 2
    assert rows[0]["path"].endswith("svchost.exe")
    assert rows[0]["last_modified_utc"].endswith("Z")
    assert rows[0]["control_set"] == "ControlSet001"


def test_raw_blob_json(tmp_path):
    blob = win10_blob([(r"C:\a.exe", D)])
    (tmp_path / "appcompatcache.bin").write_bytes(blob)
    out = tmp_path / "b.json"
    rc = main([str(tmp_path / "appcompatcache.bin"), "--json", str(out), "-q"])
    assert rc == 0
    assert json.loads(out.read_text())[0]["path"] == r"C:\a.exe"


def test_grep_and_executed_only(tmp_path):
    blob = win7_blob([
        (r"C:\Windows\notepad.exe", D, True),
        (r"C:\temp\a.tmp", D, False),
        (r"C:\temp\b.exe", D, True),
    ])
    (tmp_path / "SYSTEM").write_bytes(system_hive_with_shimcache(blob))
    out = tmp_path / "g.csv"
    main([str(tmp_path / "SYSTEM"), "--grep", r"\\temp\\", "--executed-only",
          "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert [r["path"] for r in rows] == [r"C:\temp\b.exe"]


def test_missing_file(tmp_path):
    assert main([str(tmp_path / "nope")]) == 1
