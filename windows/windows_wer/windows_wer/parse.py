"""Parse a single ``.wer`` report file."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_SIG_ALIASES = {
    "application name": "AppName", "app name": "AppName",
    "application version": "AppVersion", "app version": "AppVersion",
    "application timestamp": "AppTimeStamp",
    "fault module name": "ModName", "faulting module name": "ModName",
    "fault module version": "ModVersion",
    "fault module timestamp": "ModTimeStamp",
    "fault module offset": "ExceptionOffset",
    "exception code": "ExceptionCode", "exception offset": "ExceptionOffset",
    "exception type": "ExceptionCode",
    "package full name": "PackageFullName",
    "hang signature": "HangSig1",
}

# EventType -> Sig[n].Name ordering for the common report kinds
_SIG_MAPS = {
    "APPCRASH": ["AppName", "AppVersion", "AppTimeStamp", "ModName",
                 "ModVersion", "ModTimeStamp", "ExceptionCode",
                 "ExceptionOffset"],
    "BEX": ["AppName", "AppVersion", "AppTimeStamp", "ModName", "ModVersion",
            "ModTimeStamp", "ExceptionOffset", "ExceptionCode", "Data"],
    "BEX64": ["AppName", "AppVersion", "AppTimeStamp", "ModName",
              "ModVersion", "ModTimeStamp", "ExceptionOffset",
              "ExceptionCode", "Data"],
    "APPHANG": ["AppName", "AppVersion", "AppTimeStamp", "HangSig1",
                "HangSig2"],
    "MoAppHang": ["AppName", "AppVersion", "AppTimeStamp"],
}


@dataclass
class WerReport:
    source: str
    event_type: str = ""
    event_time: str = ""
    consent: str = ""
    report_id: str = ""
    report_status: str = ""
    app_name: str = ""
    app_path: str = ""
    app_version: str = ""
    mod_name: str = ""
    mod_path: str = ""
    mod_version: str = ""
    exception_code: str = ""
    exception_offset: str = ""
    friendly: str = ""
    pid: str = ""
    sig: dict = field(default_factory=dict)
    dynamic_sig: dict = field(default_factory=dict)
    loaded_modules: list = field(default_factory=list)
    os_version: str = ""
    parse_error: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "time": self.event_time, "event_type": self.event_type,
            "app_name": self.app_name, "app_path": self.app_path,
            "app_version": self.app_version, "mod_name": self.mod_name,
            "mod_path": self.mod_path, "exception_code": self.exception_code,
            "exception_offset": self.exception_offset, "pid": self.pid,
            "friendly": self.friendly, "report_id": self.report_id,
            "report_status": self.report_status, "consent": self.consent,
            "os_version": self.os_version,
            "loaded_modules": len(self.loaded_modules),
            "source": self.source, "notable": ";".join(self.notable),
        }


def _decode(raw: bytes) -> str:
    if raw[:2] == b"\xff\xfe":
        return raw.decode("utf-16-le", "replace")
    if raw[:2] == b"\xfe\xff":
        return raw.decode("utf-16-be", "replace")
    if b"\x00" in raw[:64]:
        return raw.decode("utf-16-le", "replace")
    return raw.decode("utf-8", "replace")


def _ft(v: str) -> str:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=n // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


def parse_wer(raw: bytes, source: str) -> WerReport:
    r = WerReport(source=source)
    try:
        text = _decode(raw)
    except Exception as e:  # noqa: BLE001
        r.parse_error = str(e)
        return r

    kv: dict[str, str] = {}
    sig_name: dict[int, str] = {}
    sig_val: dict[int, str] = {}
    dsig_name: dict[int, str] = {}
    dsig_val: dict[int, str] = {}
    for line in text.splitlines():
        line = line.strip("﻿ \t\r")
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        m = re.match(r"Sig\[(\d+)\]\.(Name|Value)$", key)
        if m:
            (sig_name if m.group(2) == "Name" else sig_val)[
                int(m.group(1))] = val
            continue
        m = re.match(r"DynamicSig\[(\d+)\]\.(Name|Value)$", key)
        if m:
            (dsig_name if m.group(2) == "Name" else dsig_val)[
                int(m.group(1))] = val
            continue
        m = re.match(r"LoadedModule\[(\d+)\]$", key)
        if m:
            r.loaded_modules.append(val)
            continue
        kv[key] = val

    for i, name in sig_name.items():
        if name:
            canon = _SIG_ALIASES.get(name.strip().lower(), name)
            r.sig[canon] = sig_val.get(i, "")
    for i, name in dsig_name.items():
        if name:
            r.dynamic_sig[name] = dsig_val.get(i, "")
    # positional fallback when Sig[n].Name is absent
    et = kv.get("EventType", "")
    if not r.sig and et in _SIG_MAPS and sig_val:
        for i, field_name in enumerate(_SIG_MAPS[et]):
            if i in sig_val:
                r.sig[field_name] = sig_val[i]

    r.event_type = et
    r.event_time = _ft(kv.get("EventTime", ""))
    r.consent = kv.get("Consent", "")
    r.report_id = kv.get("ReportIdentifier", "")
    r.report_status = kv.get("ReportStatus", "") or kv.get("Response.type", "")
    r.friendly = kv.get("FriendlyEventName", "")
    r.os_version = kv.get("OsVersion", "") or r.dynamic_sig.get("OS Version",
                                                               "")
    r.pid = (kv.get("TargetAppId", "") or r.dynamic_sig.get("ProcessId", "")
             or kv.get("ProcessId", ""))

    r.app_name = r.sig.get("AppName", "") or kv.get("AppName", "")
    r.app_version = r.sig.get("AppVersion", "")
    r.mod_name = r.sig.get("ModName", "")
    r.mod_version = r.sig.get("ModVersion", "")
    r.exception_code = r.sig.get("ExceptionCode", "")
    r.exception_offset = r.sig.get("ExceptionOffset", "")

    # AppPath / ModPath: from the explicit keys, or from a loaded module or
    # UI string that ends in the app / module name
    r.app_path = kv.get("AppPath", "")
    if not r.app_path and r.app_name:
        for v in list(kv.values()) + r.loaded_modules:
            if v.lower().endswith("\\" + r.app_name.lower()):
                r.app_path = v
                break
    r.mod_path = kv.get("ModPath", "")
    if not r.mod_path and r.mod_name:
        for v in list(kv.values()) + r.loaded_modules:
            if v.lower().endswith("\\" + r.mod_name.lower()):
                r.mod_path = v
                break
    return r
