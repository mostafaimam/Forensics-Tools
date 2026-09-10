"""Build synthetic SUM databases (SystemIdentity.mdb + Current.mdb)."""

from __future__ import annotations

from datetime import datetime, timezone

import _ese_build as E

ROLE_FILE = "{10A9226F-50EE-49D8-A393-9A501D47CE04}"
ROLE_RDS = "{4116A1D3-9C0E-46C9-9CFC-96AB4E44F8E5}"


def build_identity() -> bytes:
    role_ids = E.Table("ROLE_IDS", objid=10, fdp=10, columns=[
        E.Column(1, "RoleGuid", E.GUID),
        E.Column(256, "ProductName", E.LONG_TEXT),
        E.Column(257, "RoleName", E.LONG_TEXT),
    ], rows=[
        {"RoleGuid": ROLE_FILE.strip("{}"),
         "ProductName": "File Server", "RoleName": "File Server"},
        {"RoleGuid": ROLE_RDS.strip("{}"),
         "ProductName": "Remote Desktop Services",
         "RoleName": "Remote Desktop Services"},
    ])
    sysid = E.Table("SYSTEM_IDENTITY", objid=11, fdp=11, columns=[
        E.Column(1, "CreationTime", E.DATE_TIME),
        E.Column(2, "OSBuildNumber", E.LONG),
        E.Column(256, "OSSerialNumber", E.LONG_TEXT),
    ], rows=[
        {"CreationTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
         "OSBuildNumber": 20348, "OSSerialNumber": "00000-00000"},
    ])
    return E.build([role_ids, sysid])


def _role_table(name, objid, fdp, rows):
    cols = [
        E.Column(1, "RoleGuid", E.GUID),
        E.Column(2, "TenantId", E.GUID),
        E.Column(3, "TotalAccesses", E.LONG),
        E.Column(4, "TotalActivityDuration", E.LONG),
        E.Column(5, "FirstSeen", E.DATE_TIME),
        E.Column(6, "LastSeen", E.DATE_TIME),
        E.Column(7, "Day1", E.LONG),
        E.Column(8, "Day75", E.LONG),
        E.Column(9, "AddressLength", E.LONG),
        E.Column(256, "AuthenticatedUserName", E.LONG_TEXT),
        E.Column(257, "ClientName", E.LONG_TEXT),
        E.Column(258, "Address", E.LONG_BINARY),
    ]
    return E.Table(name, objid=objid, fdp=fdp, columns=cols, rows=rows)


def build_current() -> bytes:
    fs = datetime(2026, 1, 2, 8, 0, tzinfo=timezone.utc)
    ls = datetime(2026, 3, 16, 17, 30, tzinfo=timezone.utc)
    ip_priv = bytes([10, 0, 0, 25]) + b"\x00" * 12
    ip_pub = bytes([45, 9, 148, 20]) + b"\x00" * 12

    filesrv = _role_table(ROLE_FILE, 20, 20, [
        {"RoleGuid": ROLE_FILE.strip("{}"),
         "TenantId": "00000000-0000-0000-0000-000000000000",
         "TotalAccesses": 42, "TotalActivityDuration": 3600,
         "FirstSeen": fs, "LastSeen": ls, "Day1": 5, "Day75": 12,
         "Address": ip_priv, "AddressLength": 4,
         "AuthenticatedUserName": "CORP\\jsmith", "ClientName": "WKS-12"},
    ])
    rds = _role_table(ROLE_RDS, 21, 21, [
        {"RoleGuid": ROLE_RDS.strip("{}"),
         "TenantId": "00000000-0000-0000-0000-000000000000",
         "TotalAccesses": 130, "TotalActivityDuration": 90000,
         "FirstSeen": fs, "LastSeen": ls, "Day1": 0, "Day75": 130,
         "Address": ip_pub, "AddressLength": 4,
         "AuthenticatedUserName": "CORP\\administrator", "ClientName": ""},
    ])
    return E.build([filesrv, rds])
