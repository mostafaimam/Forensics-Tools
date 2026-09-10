"""Indicator detectors. Each yields Finding objects from the datasets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

_WIPERS = re.compile(
    r"\b(sdelete(64)?|cipher\.exe|bleachbit|ccleaner|eraser|"
    r"privazer|wipefile|sysinternals.*sdelete|dban|blank\s?and\s?secure|"
    r"freeraser|hardwipe|killdisk|active@\s?kill)\b", re.I)
_HIST_CLEAR = re.compile(
    r"\b(Clear-History|Remove-Item.*ConsoleHost_history|"
    r"Set-PSReadlineOption.*SaveNothing|wevtutil\s+cl|Clear-EventLog|"
    r"fsutil\s+usn\s+deletejournal|auditpol\s+/clear|"
    r"Clear-RecycleBin)\b", re.I)
_DISABLE_KEYS = {
    "enableprefetcher": "Prefetch disabled (EnablePrefetcher = 0)",
    "enablesuperfetch": "SuperFetch disabled",
    "disableantispyware": "Defender disabled (DisableAntiSpyware = 1)",
    "disablerealtimemonitoring": "Defender real-time protection disabled",
    "start": None,   # handled specially for SysMain/Sgrmap
}


@dataclass
class Finding:
    id: str
    severity: str          # info | low | medium | high
    title: str
    detail: str
    evidence: list = field(default_factory=list)
    times: list = field(default_factory=list)
    tool: str = ""

    def row(self) -> dict:
        return {"id": self.id, "severity": self.severity, "title": self.title,
                "detail": self.detail, "tool": self.tool,
                "times": "; ".join(self.times),
                "evidence": " || ".join(self.evidence[:6])}


_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _get(row, *names):
    low = {k.lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in low and low[n.lower()] not in (None, ""):
            return low[n.lower()]
    return ""


def _parse_ts(s):
    s = str(s or "")[:19].replace(" ", "T")
    try:
        return datetime.fromisoformat(s.rstrip("Z"))
    except ValueError:
        return None


# -- detectors --------------------------------------------------------

def d_eventlog_cleared(ds):
    for d in ds:
        if d.tool != "windows_evtx":
            continue
        for r in d.rows:
            eid = str(_get(r, "event_id", "eventid"))
            if eid in ("1102", "104", "517"):
                yield Finding(
                    "eventlog-cleared", "high",
                    "Event log cleared",
                    f"Event {eid} ({_get(r, 'channel') or 'log'} cleared) "
                    f"by {_get(r, 'user', 'subjectusername') or 'unknown'}",
                    evidence=[str(r)[:300]],
                    times=[_get(r, "time", "time_created", "timestamp")],
                    tool="windows_evtx")


def d_evtx_record_gaps(ds):
    for d in ds:
        if d.tool != "windows_evtx":
            continue
        ids = []
        for r in d.rows:
            v = _get(r, "record_id", "eventrecordid")
            if str(v).isdigit():
                ids.append(int(v))
        if len(ids) < 20:
            continue
        ids.sort()
        gaps = [(a, b) for a, b in zip(ids, ids[1:]) if b - a > 50]
        missing = sum(b - a - 1 for a, b in gaps)
        if missing > 100:
            yield Finding(
                "evtx-record-gap", "medium",
                "Gaps in the event-log record sequence",
                f"{missing} record IDs missing across {len(gaps)} gap(s) "
                f"(largest {max(b - a for a, b in gaps)})",
                evidence=[f"{a} -> {b}" for a, b in gaps[:6]],
                tool="windows_evtx")


def d_timestomp(ds):
    for d in ds:
        if d.tool != "windows_mft":
            continue
        stomped = []
        for r in d.rows:
            note = _get(r, "notable", "flags", "anomaly").lower()
            si = _get(r, "si_created", "$si_created", "created")
            fn = _get(r, "fn_created", "$fn_created")
            if "timestomp" in note or "stomp" in note or (
                    si and fn and si[:10] and fn[:10] and si < fn):
                stomped.append(_get(r, "path", "name") or str(r)[:120])
            elif si.endswith((".0000000Z", ".000000Z", ":00Z")) and \
                    _get(r, "si_modified", "modified"):
                pass
        if stomped:
            yield Finding(
                "timestomp", "high", "Timestamp manipulation ($SI vs $FN)",
                f"{len(stomped)} file(s) with $SI earlier than $FN or a "
                f"timestomp flag",
                evidence=stomped[:8], tool="windows_mft")


def d_wiper_execution(ds):
    for d in ds:
        if d.tool not in ("windows_prefetch", "windows_amcache",
                          "windows_mft", "windows_pslogging"):
            continue
        for r in d.rows:
            blob = " ".join(str(v) for v in r.values())
            if _WIPERS.search(blob):
                m = _WIPERS.search(blob)
                yield Finding(
                    "wiper-tool", "high",
                    "Secure-deletion / wiping tool present or executed",
                    f"'{m.group(0)}' seen in {d.tool} output",
                    evidence=[blob[:300]],
                    times=[_get(r, "last_run", "first_run", "time",
                                "created")],
                    tool=d.tool)


def d_history_clearing(ds):
    for d in ds:
        for r in d.rows:
            blob = " ".join(str(v) for v in r.values())
            m = _HIST_CLEAR.search(blob)
            if m:
                yield Finding(
                    "history-clear", "high",
                    "Log / history / journal clearing command",
                    f"'{m.group(0)}' in {d.tool} output",
                    evidence=[blob[:300]],
                    times=[_get(r, "time", "time_created", "timestamp",
                                "last_run")],
                    tool=d.tool)


def d_disabled_telemetry(ds):
    for d in ds:
        if d.tool != "windows_registry":
            continue
        for r in d.rows:
            name = _get(r, "value_name", "name", "value").lower()
            data = str(_get(r, "value_data", "data", "value"))
            key = _get(r, "key_path", "key", "path").lower()
            for k, msg in _DISABLE_KEYS.items():
                if k in name and msg:
                    if k == "enableprefetcher" and data.strip() not in \
                            ("0", "0x0"):
                        continue
                    yield Finding(
                        "telemetry-off", "medium", "Forensic telemetry "
                        "disabled", msg,
                        evidence=[f"{key}\\{name} = {data}"],
                        times=[_get(r, "last_written", "time")],
                        tool="windows_registry")
            if "sysmain" in key and name == "start" and data.strip() in \
                    ("4", "0x4"):
                yield Finding("telemetry-off", "medium",
                              "Forensic telemetry disabled",
                              "SysMain (SRUM/SuperFetch) service disabled "
                              "(Start = 4)",
                              evidence=[f"{key}\\Start = {data}"],
                              tool="windows_registry")


def d_defender_off(ds):
    for d in ds:
        if d.tool != "windows_defender":
            continue
        for r in d.rows:
            note = _get(r, "notable").lower()
            if "tamper" in note or "disabled" in note or "exclusion covers" \
                    in note:
                yield Finding(
                    "defender-off", "high",
                    "Defender disabled or blinded",
                    _get(r, "notable") or _get(r, "detail"),
                    evidence=[str(r)[:300]],
                    times=[_get(r, "time")], tool="windows_defender")


def d_usn_truncated(ds):
    for d in ds:
        if d.tool not in ("windows_usn", "windows_logfile"):
            continue
        usns = [int(_get(r, "usn")) for r in d.rows
                if str(_get(r, "usn")).isdigit()]
        if not usns:
            continue
        first = min(usns)
        if first > 0x100000 and len(usns) < 5000:
            yield Finding(
                "usn-truncated", "medium",
                "$UsnJrnl looks truncated / recently reset",
                f"first recovered USN is {first:#x} but only {len(usns)} "
                f"records present - a large early portion is missing",
                evidence=[f"first USN {first}", f"records {len(usns)}"],
                tool=d.tool)


def d_deletion_burst(ds):
    for d in ds:
        if d.tool not in ("windows_usn", "windows_logfile"):
            continue
        dels = []
        for r in d.rows:
            act = (_get(r, "reason", "action", "redo_op")).lower()
            if "delet" in act or "filedelete" in act:
                ts = _parse_ts(_get(r, "time", "timestamp"))
                if ts:
                    dels.append((ts, _get(r, "name", "path", "file")))
        dels.sort()
        for i in range(len(dels)):
            j = i
            while j < len(dels) and (dels[j][0] - dels[i][0]).total_seconds() \
                    <= 120:
                j += 1
            if j - i >= 30:
                yield Finding(
                    "deletion-burst", "medium",
                    "Burst of file deletions",
                    f"{j - i} files deleted within 2 minutes starting "
                    f"{dels[i][0].isoformat()}",
                    evidence=[n for _t, n in dels[i:i + 8]],
                    times=[dels[i][0].isoformat(), dels[j - 1][0].isoformat()],
                    tool=d.tool)
                break


def d_timeline_gap(ds):
    spans = []
    for d in ds:
        ts = []
        for r in d.rows:
            t = _parse_ts(_get(r, "time", "timestamp", "time_created",
                               "last_run", "created", "submit_time"))
            if t:
                ts.append(t)
        if len(ts) >= 10:
            ts.sort()
            spans.append((d.tool, ts))
    for tool, ts in spans:
        gaps = [(a, b) for a, b in zip(ts, ts[1:])
                if (b - a).total_seconds() > 36 * 3600]
        if gaps:
            biggest = max(gaps, key=lambda g: g[1] - g[0])
            hours = (biggest[1] - biggest[0]).total_seconds() / 3600
            yield Finding(
                "timeline-gap", "low",
                f"Activity gap in {tool}",
                f"{hours:.0f}-hour gap with no records "
                f"({biggest[0].isoformat()} -> {biggest[1].isoformat()})",
                times=[biggest[0].isoformat(), biggest[1].isoformat()],
                tool=tool)


DETECTORS = [d_eventlog_cleared, d_evtx_record_gaps, d_timestomp,
             d_wiper_execution, d_history_clearing, d_disabled_telemetry,
             d_defender_off, d_usn_truncated, d_deletion_burst,
             d_timeline_gap]


def run_all(datasets) -> list[Finding]:
    out: list[Finding] = []
    for det in DETECTORS:
        try:
            out.extend(det(datasets))
        except Exception:  # noqa: BLE001
            continue
    out.sort(key=lambda f: (-_SEV.get(f.severity, 0), f.id))
    return out
