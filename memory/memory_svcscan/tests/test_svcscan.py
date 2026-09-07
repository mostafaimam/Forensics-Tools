import csv
import json

import pytest

from memory_svcscan.analyze import scan
from memory_svcscan.cli import main
from memory_svcscan.flags import flag, severity
from memory_svcscan.loader import MemoryImage
from memory_svcscan.svcscan import scan as raw_scan

import _mem


def _img(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    return MemoryImage(p)


# --------------------------------------------------------------------------
# record scanning
# --------------------------------------------------------------------------

def test_recovers_all_records(tmp_path):
    svcs = {s.name: s for s in raw_scan(_img(tmp_path))}
    assert set(svcs) == {"Schedule", "W32Time", "Dnscache", "UpdaterSvc",
                         "a7f3c1d29b"}


def test_record_fields(tmp_path):
    svcs = {s.name: s for s in raw_scan(_img(tmp_path))}
    sched = svcs["Schedule"]
    assert sched.display_name == "Task Scheduler"
    assert sched.type == "win32-share"
    assert sched.state == "RUNNING"
    assert sched.pid == 1044
    assert "svchost.exe" in sched.binary_path

    w32 = svcs["W32Time"]
    assert w32.state == "STOPPED" and w32.pid == 0

    drv = svcs["a7f3c1d29b"]
    assert drv.type == "kernel-driver"
    assert drv.binary_path.endswith("drv.sys")


def test_confidence_high_when_complete(tmp_path):
    svcs = raw_scan(_img(tmp_path))
    assert all(s.confidence == "high" for s in svcs)


# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

def test_flag_user_writable_and_driver():
    f = flag("evil", "\\??\\C:\\Windows\\Temp\\x.sys", "kernel-driver",
             "RUNNING")
    assert "user-writable-path" in f
    assert "driver-from-user-path" in f
    assert severity(f) == "high"


def test_flag_lolbin_service_binary():
    f = flag("Svc", "C:\\Windows\\System32\\rundll32.exe evil.dll,Run",
             "win32-own", "RUNNING")
    assert "lolbin-service-binary" in f


def test_flag_random_name():
    assert "random-name" in flag(
        "8f3a9c2b1e7d", "C:\\Windows\\System32\\svchost.exe", "win32-share",
        "RUNNING")


def test_flag_clean_service():
    assert flag("Dnscache",
                "C:\\Windows\\System32\\svchost.exe -k NetworkService",
                "win32-own", "RUNNING") == []


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------

def test_scan_sorts_flagged_first(tmp_path):
    rows = scan(_img(tmp_path))
    assert rows[0].severity == "high"
    assert rows[-1].severity == "none"
    evil = next(r for r in rows if r.name == "a7f3c1d29b")
    assert {"user-writable-path", "driver-from-user-path",
            "random-name"} <= set(evil.notable)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_text(tmp_path, capsys):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    assert main([str(p)]) == 0
    out = capsys.readouterr().out
    assert "Schedule" in out and "Task Scheduler" not in out or "Schedule" in out
    assert "drv.sys" in out
    assert "user-writable-path" in out


def test_cli_csv_json(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "s.csv"
    js = tmp_path / "s.json"
    main([str(p), "--csv", str(out), "--json", str(js), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 5
    assert any(r["name"] == "a7f3c1d29b" and "driver-from-user-path"
               in r["notable"] for r in rows)
    assert json.loads(js.read_text())


def test_cli_filters(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())

    out = tmp_path / "run.csv"
    main([str(p), "--running", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["state"] == "RUNNING" for r in rows)
    assert not any(r["name"] == "W32Time" for r in rows)

    out2 = tmp_path / "drv.csv"
    main([str(p), "--type", "driver", "--csv", str(out2), "-q"])
    drv = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert len(drv) == 1 and drv[0]["name"] == "a7f3c1d29b"

    out3 = tmp_path / "n.csv"
    main([str(p), "--notable-only", "--csv", str(out3), "-q"])
    n = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert len(n) == 2

    out4 = tmp_path / "hi.csv"
    main([str(p), "--min-severity", "high", "--csv", str(out4), "-q"])
    assert list(csv.DictReader(out4.open(encoding="utf-8-sig")))


def test_cli_name_filter(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "name.csv"
    main([str(p), "--name", "task sched", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 1 and rows[0]["name"] == "Schedule"


def test_cli_missing_and_no_arg(tmp_path):
    assert main([str(tmp_path / "nope.lime")]) == 2
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    b = _mem.Builder()
    b.service("WmiSvc", "=cmd|' /C calc'!A1", 0x10, 4,
              "C:\\Windows\\Temp\\x.exe")
    p = tmp_path / "m.lime"
    p.write_bytes(b.lime())
    out = tmp_path / "o.csv"
    main([str(p), "--csv", str(out), "-q"])
    raw = out.read_text(encoding="utf-8-sig")
    assert "'=cmd|" in raw
