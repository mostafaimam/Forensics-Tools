from __future__ import annotations

import csv
import json

import pytest

from analysis_antiforensics.load import load
from analysis_antiforensics.detectors import run_all
from analysis_antiforensics.cli import main


def _csv(path, rows):
    cols = list(rows[0])
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def test_load_and_guess(tmp_path):
    p = tmp_path / "windows_evtx_security.csv"
    _csv(p, [{"time": "2026-03-16T10:00:00Z", "event_id": "4624",
              "provider": "Sec", "channel": "Security", "record_id": "1"}])
    ds = load([str(tmp_path)])
    assert ds and ds[0].tool == "windows_evtx"


def test_eventlog_cleared(tmp_path):
    p = tmp_path / "evtx.csv"
    _csv(p, [{"time": "2026-03-16T11:00:00Z", "event_id": "1102",
              "provider": "Eventlog", "channel": "Security",
              "record_id": "500", "user": "WS01\\attacker"}])
    finds = run_all(load([str(p)]))
    assert any(f.id == "eventlog-cleared" and f.severity == "high"
               for f in finds)


def test_record_gap(tmp_path):
    rows = [{"time": "t", "event_id": "1", "provider": "p", "channel": "c",
             "record_id": str(i)} for i in list(range(1, 30)) +
            list(range(400, 430))]
    p = tmp_path / "windows_evtx.csv"
    _csv(p, rows)
    finds = run_all(load([str(p)]))
    assert any(f.id == "evtx-record-gap" for f in finds)


def test_timestomp_and_wiper(tmp_path):
    _csv(tmp_path / "windows_mft.csv", [
        {"path": "C:\\evil.exe", "si_created": "2020-01-01T00:00:00Z",
         "fn_created": "2026-03-16T09:00:00Z", "notable": ""},
        {"path": "C:\\ok.dll", "si_created": "2026-01-01T00:00:00Z",
         "fn_created": "2026-01-01T00:00:00Z", "notable": ""}])
    _csv(tmp_path / "windows_prefetch.csv", [
        {"name": "SDELETE64.EXE", "run_count": "3",
         "last_run": "2026-03-16T11:05:00Z"}])
    finds = run_all(load([str(tmp_path)]))
    ids = {f.id for f in finds}
    assert "timestomp" in ids
    assert "wiper-tool" in ids


def test_deletion_burst(tmp_path):
    rows = []
    for i in range(40):
        rows.append({"time": f"2026-03-16T12:00:{i % 60:02d}Z",
                     "usn": str(1000 + i), "reason": "FileDelete|Close",
                     "name": f"doc{i}.docx"})
    _csv(tmp_path / "windows_usn.csv", rows)
    finds = run_all(load([str(tmp_path)]))
    assert any(f.id == "deletion-burst" for f in finds)


def test_defender_off(tmp_path):
    _csv(tmp_path / "windows_defender.csv", [
        {"time": "2026-03-16T09:40:00Z", "kind": "protection-setting",
         "severity": "high",
         "notable": "protection setting changed;real-time protection "
                    "disabled", "detail": ""}])
    finds = run_all(load([str(tmp_path)]))
    assert any(f.id == "defender-off" for f in finds)


def test_cli_html_json(tmp_path):
    _csv(tmp_path / "evtx.csv", [
        {"time": "2026-03-16T11:00:00Z", "event_id": "1102",
         "provider": "Eventlog", "channel": "Security", "record_id": "9"}])
    _csv(tmp_path / "windows_pslogging.csv", [
        {"time": "2026-03-16T11:02:00Z", "kind": "scriptblock",
         "scriptblock_id": "x", "text": "wevtutil cl System",
         "notable": "clears event logs"}])
    html_p = tmp_path / "af.html"
    js_p = tmp_path / "af.json"
    rc = main([str(tmp_path), "--html", str(html_p), "--json", str(js_p),
               "-q"])
    assert rc == 1   # medium/high findings -> nonzero
    assert "Anti-forensics" in html_p.read_text()
    data = json.loads(js_p.read_text())
    assert any(r["id"] == "eventlog-cleared" for r in data)
    assert any(r["id"] == "history-clear" for r in data)


def test_clean_case(tmp_path):
    _csv(tmp_path / "windows_prefetch.csv", [
        {"name": "NOTEPAD.EXE", "run_count": "5",
         "last_run": "2026-03-16T09:00:00Z"}])
    rc = main([str(tmp_path), "-q"])
    assert rc == 0


def test_csv_injection_guard():
    from analysis_antiforensics.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
