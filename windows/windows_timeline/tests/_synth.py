"""Build a synthetic ActivitiesCache.db for the windows_timeline test-suite."""

from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime, timezone


def _epoch(dt):
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def _appid(win32=None, packaged=None):
    arr = []
    if win32:
        arr.append({"application": win32, "platform": "windows_win32"})
    if packaged:
        arr.append({"application": packaged, "platform": "packageId"})
    return json.dumps(arr)


def _clip(text):
    return json.dumps([{"formatName": "Text",
                        "content": base64.b64encode(
                            text.encode("utf-16-le")).decode()}])


def build(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE Activity (
        Id BLOB, AppId TEXT, ActivityType INT, Payload TEXT,
        ClipboardPayload TEXT, StartTime INT, EndTime INT,
        LastModifiedTime INT, ExpirationTime INT, IsLocalOnly INT,
        CreatedInCloud INT)""")
    con.execute("""CREATE TABLE ActivityOperation (
        Id BLOB, AppId TEXT, ActivityType INT, Payload TEXT,
        ClipboardPayload TEXT, StartTime INT, EndTime INT,
        LastModifiedTime INT, ExpirationTime INT, IsLocalOnly INT,
        CreatedInCloud INT)""")

    base = datetime(2026, 3, 7, 9, 0)
    rows = [
        (b"\x01" * 16, _appid(win32="C:\\Program Files\\Microsoft Office\\"
                              "root\\Office16\\WINWORD.EXE"),
         5, json.dumps({"displayText": "Q1 report.docx",
                        "contentUri": "file:///C:/Users/victim/Documents/"
                        "Q1%20report.docx", "appDisplayName": "Word"}),
         None, _epoch(base), _epoch(base.replace(minute=25)),
         _epoch(base.replace(minute=25)), 0, 1, 0),
        (b"\x02" * 16, _appid(win32="C:\\Users\\victim\\AppData\\Local\\Temp\\"
                              "agent.exe"),
         5, json.dumps({"displayText": "agent.exe",
                        "contentUri": "file:///C:/Users/victim/AppData/Local/"
                        "Temp/agent.exe"}),
         None, _epoch(base.replace(minute=30)),
         _epoch(base.replace(minute=31)),
         _epoch(base.replace(minute=31)), 0, 1, 0),
        (b"\x03" * 16, _appid(win32="C:\\Windows\\System32\\"
                              "WindowsPowerShell\\v1.0\\powershell.exe"),
         5, json.dumps({"displayText": "Windows PowerShell"}),
         None, _epoch(base.replace(minute=35)),
         _epoch(base.replace(minute=40)),
         _epoch(base.replace(minute=40)), 0, 0, 0),
        (b"\x04" * 16, _appid(packaged="Microsoft.WindowsNotepad_8wekyb3d8bbwe"
                              "!App"),
         10, "{}", _clip("aws_secret_access_key = AKIA000EXAMPLE0KEY"),
         _epoch(base.replace(minute=45)), _epoch(base.replace(minute=45)),
         _epoch(base.replace(minute=45)), 0, 1, 0),
    ]
    con.executemany("INSERT INTO Activity VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    op_row = (b"\x09" * 16, _appid(win32="C:\\Windows\\System32\\cmd.exe"),
              6, json.dumps({"displayText": "removed activity"}),
              None, _epoch(base.replace(hour=8)),
              _epoch(base.replace(hour=8, minute=1)),
              _epoch(base.replace(hour=8, minute=1)), 0, 1, 0)
    con.execute("INSERT INTO ActivityOperation VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                op_row)
    con.commit()
    con.close()
    return path
