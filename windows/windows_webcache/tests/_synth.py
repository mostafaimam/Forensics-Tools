"""Build a synthetic WebCacheV01.dat for the windows_webcache test-suite."""

from __future__ import annotations

from datetime import datetime, timezone

import _ese_build as E

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def build() -> bytes:
    m = ft(datetime(2026, 3, 4, 9, 0, tzinfo=timezone.utc))
    a1 = ft(datetime(2026, 3, 4, 9, 5, tzinfo=timezone.utc))
    a2 = ft(datetime(2026, 3, 4, 12, 0, tzinfo=timezone.utc))
    exp = ft(datetime(2027, 3, 4, tzinfo=timezone.utc))

    containers = E.Table("Containers", objid=10, fdp=10, columns=[
        E.Column(1, "ContainerId", E.LONG),
        E.Column(2, "SetId", E.LONG),
        E.Column(128, "Name", E.TEXT),
        E.Column(129, "Directory", E.TEXT),
    ], rows=[
        {"ContainerId": 1, "SetId": 0, "Name": "History",
         "Directory": "History.IE5"},
        {"ContainerId": 2, "SetId": 0, "Name": "Cookies",
         "Directory": "Cookies"},
        {"ContainerId": 3, "SetId": 0, "Name": "Content",
         "Directory": "IE\\Cache"},
        {"ContainerId": 4, "SetId": 0, "Name": "iedownload",
         "Directory": "IEDownloadHistory"},
    ])

    def container_table(objid, fdp, rows):
        return E.Table(f"Container_{objid}", objid=objid, fdp=fdp, columns=[
            E.Column(1, "EntryId", E.LONG),
            E.Column(2, "ContainerId", E.LONG),
            E.Column(3, "AccessCount", E.LONG),
            E.Column(4, "FileSize", E.LONG_LONG),
            E.Column(5, "ModifiedTime", E.LONG_LONG),
            E.Column(6, "AccessedTime", E.LONG_LONG),
            E.Column(7, "ExpiryTime", E.LONG_LONG),
            E.Column(8, "SyncTime", E.LONG_LONG),
            E.Column(128, "Filename", E.TEXT),
            E.Column(256, "Url", E.LONG_TEXT),
        ], rows=rows)

    history = container_table(11, 11, [
        {"EntryId": 1, "ContainerId": 1, "AccessCount": 3,
         "ModifiedTime": m, "AccessedTime": a1,
         "Url": "Visited: victim@http://intranet.corp/wiki"},
        {"EntryId": 2, "ContainerId": 1, "AccessCount": 1,
         "ModifiedTime": m, "AccessedTime": a2,
         "Url": "Visited: victim@https://pastebin.com/raw/AbCdEf12"},
        {"EntryId": 3, "ContainerId": 1, "AccessCount": 1,
         "ModifiedTime": m, "AccessedTime": a2,
         "Url": "Visited: victim@http://185.10.20.30/panel/"},
    ])
    cookies = container_table(12, 12, [
        {"EntryId": 1, "ContainerId": 2, "AccessCount": 5,
         "ModifiedTime": m, "AccessedTime": a1, "ExpiryTime": exp,
         "Filename": "ABCD1234.cookie",
         "Url": "Cookie:victim@ngrok-free.app/"},
    ])
    content = container_table(13, 13, [
        {"EntryId": 1, "ContainerId": 3, "AccessCount": 1,
         "ModifiedTime": m, "AccessedTime": a1, "FileSize": 4096,
         "Filename": "logo[1].png",
         "Url": "http://intranet.corp/img/logo.png"},
    ])
    downloads = container_table(14, 14, [
        {"EntryId": 1, "ContainerId": 4, "AccessCount": 1,
         "ModifiedTime": m, "AccessedTime": a2, "FileSize": 2_500_000,
         "Filename": "tool.exe",
         "Url": "http://185.10.20.30/files/tool.exe"},
    ])

    return E.build([containers, history, cookies, content, downloads])
