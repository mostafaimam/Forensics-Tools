"""Extract the forensically useful Defender Operational-log events."""

from __future__ import annotations

from dataclasses import dataclass

from windows_defender.evtx import EvtxError, parse_evtx

# event id -> (short label, kind)
_EVENTS = {
    "1006": ("malware detected", "detection"),
    "1007": ("action taken", "action"),
    "1008": ("action failed", "action"),
    "1009": ("item restored from quarantine", "action"),
    "1010": ("could not restore item", "action"),
    "1011": ("item deleted from quarantine", "action"),
    "1015": ("suspicious behaviour detected", "detection"),
    "1116": ("malware detected", "detection"),
    "1117": ("action taken", "action"),
    "1118": ("remediation started", "action"),
    "1119": ("remediation failed - critical", "action"),
    "1120": ("attack surface reduction rule fired", "detection"),
    "1121": ("attack surface reduction rule blocked", "detection"),
    "1150": ("service healthy", "health"),
    "1151": ("health report", "health"),
    "2000": ("signatures updated", "signature"),
    "2001": ("signature update failed", "signature"),
    "2002": ("engine updated", "signature"),
    "2003": ("engine update failed", "signature"),
    "2010": ("signatures rolled back / dynamic", "signature"),
    "2050": ("offline scan requested", "scan"),
    "3002": ("real-time protection feature failed", "tamper"),
    "5001": ("real-time protection disabled", "tamper"),
    "5004": ("real-time protection configuration changed", "tamper"),
    "5007": ("configuration changed", "tamper"),
    "5008": ("engine crashed", "tamper"),
    "5010": ("scanning for malware disabled", "tamper"),
    "5012": ("scanning for viruses disabled", "tamper"),
    "5013": ("tamper protection blocked a change", "tamper"),
    "1002": ("scan stopped before completion", "scan"),
}

_FIELDS = ("Threat Name", "Threat ID", "Severity Name", "Category Name",
           "Path", "Detection User", "Process Name", "Action Name",
           "Action ID", "Origin Name", "Detection Time", "Old Value",
           "New Value", "Product Name", "Source Name", "Remediation User",
           "Error Description", "FWLink", "Signature Version",
           "Current Signature Version", "Engine Version")


@dataclass
class DefEvent:
    time: str
    event_id: str
    label: str
    kind: str
    computer: str
    threat: str
    path: str
    user: str
    process: str
    action: str
    detail: str
    source: str

    def row(self) -> dict:
        return {
            "kind": f"evtx-{self.kind}", "time": self.time,
            "event_id": self.event_id, "computer": self.computer,
            "threat": self.threat, "path": self.path, "user": self.user,
            "process": self.process, "action": self.action,
            "detail": (self.label + " | " + self.detail).strip(" |")[:500],
            "source": self.source,
        }


def _norm(k: str) -> str:
    return (k or "").split("/")[-1].strip()


def parse_defender_evtx(data: bytes, source: str) -> tuple[list[DefEvent],
                                                           list[str]]:
    out: list[DefEvent] = []
    errs: list[str] = []
    try:
        events = list(parse_evtx(data))
    except EvtxError as e:
        return out, [f"{source}: {e}"]
    for r in events:
        eid = str(r.event_id)
        if eid not in _EVENTS:
            continue
        label, kind = _EVENTS[eid]
        d = {_norm(k): v for k, v in r.data.items()}
        pieces = []
        for f in _FIELDS:
            if d.get(f):
                pieces.append(f"{f}={d[f]}")
        out.append(DefEvent(
            time=(r.time_created_utc or r.timestamp_utc or "").replace(
                ".000000Z", "Z"),
            event_id=eid, label=label, kind=kind, computer=r.computer or "",
            threat=d.get("Threat Name", "") or d.get("Threat ID", ""),
            path=d.get("Path", "") or "",
            user=d.get("Detection User", "") or d.get("Remediation User", "")
            or d.get("Detection User Name", ""),
            process=d.get("Process Name", "") or d.get("Source Name", ""),
            action=d.get("Action Name", "") or d.get("Action ID", ""),
            detail="; ".join(pieces), source=source))
    return out, errs
