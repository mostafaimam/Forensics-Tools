"""Synthetic Defender Operational EVTX + an MPLog sample."""

from __future__ import annotations

import _evtx_synth as E

CH = "Microsoft-Windows-Windows Defender/Operational"
PROV = "Microsoft-Windows-Windows Defender"


def _ev(eid, data, *, level="4", time):
    return E.event_fragment(event_id=str(eid), provider=PROV, level=level,
                            channel=CH, computer="WS01",
                            time_created=time, data=data)


def build_evtx() -> bytes:
    frags = [
        _ev(1116, {
            "Threat Name": "Trojan:Win32/Wacatac.B!ml",
            "Severity Name": "Severe", "Category Name": "Trojan",
            "Path": "file:_C:\\Users\\victim\\Downloads\\invoice.exe",
            "Detection User": "WS01\\victim",
            "Process Name": "C:\\Windows\\explorer.exe",
        }, time="2026-03-16T10:15:00.000000Z"),
        _ev(1117, {
            "Threat Name": "Trojan:Win32/Wacatac.B!ml",
            "Action Name": "Quarantine", "Action ID": "2",
            "Path": "file:_C:\\Users\\victim\\Downloads\\invoice.exe",
            "Detection User": "WS01\\victim",
        }, time="2026-03-16T10:15:02.000000Z"),
        _ev(5007, {
            "Old Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\"
                         "Real-Time Protection\\DisableRealtimeMonitoring "
                         "= 0x0",
            "New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\"
                         "Real-Time Protection\\DisableRealtimeMonitoring "
                         "= 0x1",
        }, time="2026-03-16T09:40:00.000000Z"),
        _ev(5001, {"Product Name": "Microsoft Defender Antivirus"},
            time="2026-03-16T09:41:00.000000Z"),
        _ev(2001, {
            "Error Description": "The signature update failed.",
            "Signature Version": "1.401.1234.0",
            "Current Signature Version": "1.401.1000.0",
        }, time="2026-03-15T02:00:00.000000Z"),
    ]
    return E.build_evtx(frags)


MPLOG = """\
2026-03-16T09:00:01.111Z BEGIN SCAN Manual ...
2026-03-16T09:00:02.222Z ProcessImageName: powershell.exe, Pid: 4512, TotalTime: 800, Count: 3
2026-03-16T09:00:03.333Z Lowfi: [processPath: \\Device\\HarddiskVolume2\\Users\\victim\\AppData\\Local\\Temp\\a.exe]
2026-03-16T10:15:00.000Z DETECTIONEVENT MPSOURCE_REALTIME Trojan:Win32/Wacatac.B!ml file:C:\\Users\\victim\\Downloads\\invoice.exe
2026-03-16T10:16:00.000Z DETECTION Behavior:Win32/DefenseEvasion.A!ml file:C:\\Windows\\System32\\cmd.exe
2026-03-16T11:00:00.000Z EXCLUSION added path: C:\\Users\\victim\\AppData\\Local\\Temp
2026-03-16T11:30:00.000Z END SCAN Manual ...
"""
