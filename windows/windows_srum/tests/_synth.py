"""Build a synthetic SRUDB.dat for the windows_srum test-suite."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

import _ese_build as E

NET_DATA = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
NET_CONN = "{DD6636C4-8929-4683-974E-22C046A43763}"
APP_RES = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"


def _sid_blob(sid: str) -> bytes:
    parts = sid.split("-")
    authority = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    b = struct.pack("<BB", 1, len(subs)) + authority.to_bytes(6, "big")
    for s in subs:
        b += struct.pack("<I", s)
    return b


def build() -> bytes:
    t0 = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 3, 1, 11, 0, tzinfo=timezone.utc)

    idmap = E.Table("SruDbIdMapTable", objid=10, fdp=10, columns=[
        E.Column(1, "IdType", E.LONG),
        E.Column(2, "IdIndex", E.LONG),
        E.Column(256, "IdBlob", E.LONG_BINARY),
    ], rows=[
        {"IdType": 0, "IdIndex": 101,
         "IdBlob": "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe"
         .encode("utf-16-le")},
        {"IdType": 0, "IdIndex": 102,
         "IdBlob": "C:\\Users\\victim\\AppData\\Local\\Temp\\agent.exe"
         .encode("utf-16-le")},
        {"IdType": 0, "IdIndex": 103,
         "IdBlob": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
         "powershell.exe".encode("utf-16-le")},
        {"IdType": 3, "IdIndex": 201,
         "IdBlob": _sid_blob("S-1-5-21-111-222-333-1001")},
    ])

    netdata = E.Table(NET_DATA, objid=11, fdp=11, columns=[
        E.Column(1, "AutoIncId", E.LONG),
        E.Column(2, "TimeStamp", E.DATE_TIME),
        E.Column(3, "AppId", E.LONG),
        E.Column(4, "UserId", E.LONG),
        E.Column(5, "InterfaceLuid", E.LONG_LONG),
        E.Column(6, "L2ProfileId", E.LONG),
        E.Column(7, "BytesSent", E.LONG_LONG),
        E.Column(8, "BytesRecvd", E.LONG_LONG),
    ], rows=[
        {"AutoIncId": 1, "TimeStamp": t0, "AppId": 101, "UserId": 201,
         "InterfaceLuid": 0x1234, "L2ProfileId": 5,
         "BytesSent": 20000, "BytesRecvd": 500000},
        {"AutoIncId": 2, "TimeStamp": t1, "AppId": 102, "UserId": 201,
         "InterfaceLuid": 0x1234, "L2ProfileId": 5,
         "BytesSent": 90 * 1024 * 1024, "BytesRecvd": 0},
        {"AutoIncId": 3, "TimeStamp": t1, "AppId": 103, "UserId": 201,
         "InterfaceLuid": 0x1234, "L2ProfileId": 5,
         "BytesSent": 4000, "BytesRecvd": 10000},
    ])

    appres = E.Table(APP_RES, objid=12, fdp=12, columns=[
        E.Column(1, "AutoIncId", E.LONG),
        E.Column(2, "TimeStamp", E.DATE_TIME),
        E.Column(3, "AppId", E.LONG),
        E.Column(4, "UserId", E.LONG),
        E.Column(5, "ForegroundCycleTime", E.LONG_LONG),
        E.Column(6, "BackgroundCycleTime", E.LONG_LONG),
        E.Column(7, "ForegroundBytesRead", E.LONG_LONG),
    ], rows=[
        {"AutoIncId": 1, "TimeStamp": t0, "AppId": 102, "UserId": 201,
         "ForegroundCycleTime": 5_000_000, "BackgroundCycleTime": 1_000_000,
         "ForegroundBytesRead": 12345},
    ])

    return E.build([idmap, netdata, appres])
