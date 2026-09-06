import csv
import json

from _synth import write_tree
from linux_syslog.cli import main


def _rows(p):
    return list(csv.DictReader(p.open(encoding="utf-8-sig")))


def test_records_from_file(tmp_path):
    root = write_tree(tmp_path)
    out = tmp_path / "r.csv"
    rc = main([str(root / "var/log/auth.log"), "--year", "2024",
               "--csv", str(out), "-q"])
    assert rc == 0
    rows = _rows(out)
    # continuation lines folded into myapp's record
    myapp = [r for r in rows if r["tag"] == "myapp"]
    assert len(myapp) == 1 and "config value = 42" in myapp[0]["message"]
    assert rows[0]["timestamp_utc"] <= rows[-1]["timestamp_utc"]


def test_events_and_filters(tmp_path):
    root = write_tree(tmp_path)
    out = tmp_path / "e.csv"
    rc = main([str(root / "var/log/auth.log"), "--year", "2024", "--events",
               "--csv", str(out), "-q"])
    assert rc == 0
    rows = _rows(out)
    cats = {r["category"] for r in rows}
    assert {"ssh", "sudo", "su", "session", "cron", "account"} <= cats

    out2 = tmp_path / "e2.csv"
    main([str(root / "var/log/auth.log"), "--year", "2024", "--events",
          "--category", "ssh", "--result", "failure", "--csv", str(out2), "-q"])
    r2 = _rows(out2)
    assert r2 and all(r["category"] == "ssh" and r["result"] == "failure"
                      for r in r2)
    assert any(r["source_ip"] == "198.51.100.23" for r in r2)


def test_root_scan_merges_rotations_and_gz(tmp_path):
    root = write_tree(tmp_path)
    out = tmp_path / "all.json"
    rc = main([str(root), "--root", "--year", "2024", "--events",
               "--category", "ssh", "--json", str(out), "-q"])
    assert rc == 0
    data = json.loads(out.read_text())
    users = {d["user"] for d in data}
    assert {"carol", "dave", "alice", "deploy"} <= users  # .1, .2.gz, iso, main


def test_iso_offset_conversion(tmp_path):
    root = write_tree(tmp_path)
    out = tmp_path / "s.csv"
    main([str(root / "var/log/syslog"), "--events", "--csv", str(out), "-q"])
    rows = _rows(out)
    alice = next(r for r in rows if r["user"] == "alice")
    # 09:30+02:00 -> 07:30Z
    assert alice["timestamp_utc"].startswith("2024-02-10T07:30:00")


def test_rfc5424_file(tmp_path):
    from _synth import RFC5424
    f = tmp_path / "rfc5424.log"
    f.write_text(RFC5424)
    out = tmp_path / "x.csv"
    main([str(f), "--events", "--csv", str(out), "-q"])
    rows = _rows(out)
    assert any(r["category"] == "su" and r["target_user"] == "root"
               for r in rows)


def test_grep_and_severity(tmp_path):
    root = write_tree(tmp_path)
    out = tmp_path / "g.csv"
    main([str(root / "var/log/auth.log"), "--year", "2024",
          "--grep", "Accepted", "--csv", str(out), "-q"])
    rows = _rows(out)
    assert rows and all("Accepted" in r["message"] for r in rows)


def test_missing_file():
    assert main(["/no/such/log"]) == 2
