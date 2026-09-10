"""Synthetic CurrentPowerlog.PLSQL for the macos_powerlog test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def _epoch(dt):
    return dt.replace(tzinfo=timezone.utc).timestamp()


def build(path):
    con = sqlite3.connect(path)
    base = datetime(2026, 3, 14, 9, 0)

    con.execute("""CREATE TABLE PLApplicationAgent_EventForward_Application (
        ID INTEGER PRIMARY KEY, timestamp REAL, BundleID TEXT,
        Notification TEXT)""")
    con.executemany(
        "INSERT INTO PLApplicationAgent_EventForward_Application "
        "(timestamp, BundleID, Notification) VALUES (?,?,?)", [
            (_epoch(base), "com.apple.Safari", "Activated"),
            (_epoch(base.replace(hour=10)), "com.apple.Terminal",
             "Activated"),
            (_epoch(base.replace(hour=11)),
             "/Users/victim/.cache/app", "Activated"),
        ])

    con.execute("""CREATE TABLE PLProcessMonitorAgent_EventPoint_ProcessInfo (
        ID INTEGER PRIMARY KEY, timestamp REAL, ProcessName TEXT, PID INTEGER,
        State TEXT)""")
    con.executemany(
        "INSERT INTO PLProcessMonitorAgent_EventPoint_ProcessInfo "
        "(timestamp, ProcessName, PID, State) VALUES (?,?,?,?)", [
            (_epoch(base.replace(hour=10, minute=5)), "/bin/zsh", 4321,
             "start"),
            (_epoch(base.replace(hour=10, minute=6)),
             "/private/tmp/impl", 4400, "start"),
            (_epoch(base.replace(hour=10, minute=30)), "/usr/bin/vim", 4500,
             "start"),
        ])

    con.execute("""CREATE TABLE PLCameraAgent_EventForward_Camera (
        ID INTEGER PRIMARY KEY, timestamp REAL, Client TEXT, State INTEGER)""")
    con.executemany(
        "INSERT INTO PLCameraAgent_EventForward_Camera "
        "(timestamp, Client, State) VALUES (?,?,?)", [
            (_epoch(base.replace(hour=12)), "us.zoom.xos", 1),
            (_epoch(base.replace(hour=13)), "com.acme.screenspy", 1),
        ])

    con.execute("""CREATE TABLE PLLocationAgent_EventForward_ClientStatus (
        ID INTEGER PRIMARY KEY, timestamp REAL, Client TEXT,
        Latitude REAL, Longitude REAL)""")
    con.executemany(
        "INSERT INTO PLLocationAgent_EventForward_ClientStatus "
        "(timestamp, Client, Latitude, Longitude) VALUES (?,?,?,?)", [
            (_epoch(base.replace(hour=14)), "com.apple.Maps",
             37.33182, -122.03118),
            (_epoch(base.replace(hour=2, minute=30)), "com.acme.tracker",
             40.7128, -74.0060),
        ])

    con.execute("""CREATE TABLE PLBatteryAgent_EventBackward_Battery (
        ID INTEGER PRIMARY KEY, timestamp REAL, Level INTEGER)""")
    con.executemany(
        "INSERT INTO PLBatteryAgent_EventBackward_Battery "
        "(timestamp, Level) VALUES (?,?)", [
            (_epoch(base), 92), (_epoch(base.replace(hour=15)), 61)])

    # an unrecognised table (should be ignored by collect, visible to
    # --list-tables / --table)
    con.execute("CREATE TABLE PLXPCAgent_Junk (timestamp REAL, x TEXT)")
    con.execute("INSERT INTO PLXPCAgent_Junk VALUES (0, 'noise')")

    con.commit()
    con.close()
    return path
