"""Synthetic TCC.db files for the macos_tcc test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def _epoch(dt):
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


_MODERN_SCHEMA = """CREATE TABLE access (
    service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER,
    auth_reason INTEGER, auth_version INTEGER, csreq BLOB, policy_id INTEGER,
    indirect_object_identifier_type INTEGER,
    indirect_object_identifier TEXT, indirect_object_code_identity BLOB,
    flags INTEGER, last_modified INTEGER,
    PRIMARY KEY (service, client, client_type, indirect_object_identifier))"""

_OLD_SCHEMA = """CREATE TABLE access (
    service TEXT, client TEXT, client_type INTEGER, allowed INTEGER,
    prompt_count INTEGER, csreq BLOB, policy_id INTEGER,
    PRIMARY KEY (service, client, client_type))"""


def build_system(path):
    con = sqlite3.connect(path)
    con.execute(_MODERN_SCHEMA)
    t = _epoch(datetime(2026, 3, 11, 9, 0))
    con.executemany(
        "INSERT INTO access (service, client, client_type, auth_value, "
        "auth_reason, auth_version, indirect_object_identifier, flags, "
        "last_modified) VALUES (?,?,?,?,?,?,?,?,?)", [
            ("kTCCServiceSystemPolicyAllFiles",
             "/Applications/BackupTool.app", 0, 2, 2, 1, "UNUSED", 0, t),
            ("kTCCServiceAccessibility", "/usr/local/bin/helper", 1, 2, 3, 1,
             "UNUSED", 0, t),
            ("kTCCServiceScreenCapture", "com.apple.Terminal", 0, 2, 2, 1,
             "UNUSED", 0, t),
            ("kTCCServiceListenEvent", "/Users/victim/.local/bin/kbd", 1, 2, 2,
             1, "UNUSED", 0, t),
            ("kTCCServiceDeveloperTool", "com.apple.dt.Xcode", 0, 0, 2, 1,
             "UNUSED", 0, t),
        ])
    con.commit()
    con.close()
    return path


def build_user(path):
    con = sqlite3.connect(path)
    con.execute(_MODERN_SCHEMA)
    t = _epoch(datetime(2026, 3, 11, 10, 0))
    con.executemany(
        "INSERT INTO access (service, client, client_type, auth_value, "
        "auth_reason, auth_version, indirect_object_identifier, flags, "
        "last_modified) VALUES (?,?,?,?,?,?,?,?,?)", [
            ("kTCCServiceCamera", "us.zoom.xos", 0, 2, 2, 1, "UNUSED", 0, t),
            ("kTCCServiceMicrophone", "com.apple.Terminal", 0, 2, 2, 1,
             "UNUSED", 0, t),
            ("kTCCServiceAppleEvents", "com.apple.Terminal", 0, 2, 2, 1,
             "com.apple.systemevents", 0, t),
            ("kTCCServiceContactsFull", "com.acme.crm", 0, 3, 2, 1, "UNUSED",
             0, t),
        ])
    con.commit()
    con.close()
    return path


def build_old(path):
    con = sqlite3.connect(path)
    con.execute(_OLD_SCHEMA)
    con.executemany(
        "INSERT INTO access (service, client, client_type, allowed, "
        "prompt_count) VALUES (?,?,?,?,?)", [
            ("kTCCServiceAccessibility", "com.apple.Terminal", 0, 1, 1),
            ("kTCCServiceCamera", "com.example.app", 0, 0, 2),
        ])
    con.commit()
    con.close()
    return path
