import csv
import gzip
import json

from _synth import lastlog, sample_btmp, sample_wtmp
from linux_utmp.cli import main
from datetime import datetime


def test_records_csv(tmp_path):
    p = tmp_path / "wtmp"
    p.write_bytes(sample_wtmp())
    out = tmp_path / "r.csv"
    rc = main([str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 5
    assert rows[0]["timestamp_utc"] <= rows[-1]["timestamp_utc"]
    assert any(r["type"] == "USER_PROCESS" and r["user"] == "alice" for r in rows)


def test_sessions_csv(tmp_path):
    p = tmp_path / "wtmp"
    p.write_bytes(sample_wtmp())
    out = tmp_path / "s.csv"
    rc = main([str(p), "--sessions", "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 3
    bob = next(r for r in rows if r["user"] == "bob")
    assert bob["still_open"] == "yes"


def test_user_and_type_filter(tmp_path):
    p = tmp_path / "wtmp"
    p.write_bytes(sample_wtmp())
    out = tmp_path / "f.csv"
    main([str(p), "--user", "alice", "--type", "USER_PROCESS",
          "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["user"] == "alice" for r in rows)


def test_gzip_input(tmp_path):
    p = tmp_path / "wtmp.1.gz"
    p.write_bytes(gzip.compress(sample_wtmp()))
    out = tmp_path / "g.json"
    rc = main([str(p), "--json", str(out), "-q"])
    assert rc == 0
    assert len(json.loads(out.read_text())) == 5


def test_btmp_detected_by_name(tmp_path):
    p = tmp_path / "btmp"
    p.write_bytes(sample_btmp())
    out = tmp_path / "b.csv"
    main([str(p), "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 5


def test_lastlog(tmp_path):
    p = tmp_path / "lastlog"
    p.write_bytes(lastlog({1000: (datetime(2024, 5, 5), "pts/0", "host")}))
    out = tmp_path / "l.csv"
    rc = main([str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows[0]["uid"] == "1000" and rows[0]["host"] == "host"


def test_missing_file(tmp_path):
    assert main([str(tmp_path / "nope")]) == 1
