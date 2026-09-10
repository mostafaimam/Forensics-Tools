"""Read the TCC ``access`` table across schema versions."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

from macos_tcc import flags as _flags
from macos_tcc.dbopen import connect

SERVICES = {
    "kTCCServiceAll": "All",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceListenEvent": "Input Monitoring (keystrokes)",
    "kTCCServicePostEvent": "Synthetic input (post events)",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceSystemPolicyDesktopFolder": "Desktop folder",
    "kTCCServiceSystemPolicyDocumentsFolder": "Documents folder",
    "kTCCServiceSystemPolicyDownloadsFolder": "Downloads folder",
    "kTCCServiceSystemPolicyNetworkVolumes": "Network volumes",
    "kTCCServiceSystemPolicyRemovableVolumes": "Removable volumes",
    "kTCCServiceSystemPolicySysAdminFiles": "Admin files",
    "kTCCServiceDeveloperTool": "Developer Tools",
    "kTCCServiceAppleEvents": "Automation (Apple Events)",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceContactsFull": "Contacts (full)",
    "kTCCServiceContactsLimited": "Contacts (limited)",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServiceReminders": "Reminders",
    "kTCCServicePhotos": "Photos",
    "kTCCServiceMediaLibrary": "Media library",
    "kTCCServiceLocation": "Location",
    "kTCCServiceUbiquity": "iCloud",
    "kTCCServiceFileProviderPresence": "File provider",
    "kTCCServiceFileProviderDomain": "File provider domain",
    "kTCCServiceSpeechRecognition": "Speech recognition",
    "kTCCServiceWillow": "HomeKit",
    "kTCCServiceBluetoothAlways": "Bluetooth",
    "kTCCServiceMotion": "Motion & Fitness",
    "kTCCServiceProtectedCloudStorage": "Protected cloud storage",
    "kTCCServiceCalendarWrite": "Calendar (write)",
    "kTCCServiceLiverpool": "Location (Liverpool)",
    "kTCCServiceGameCenterFriends": "Game Center friends",
}


def _utc(v) -> str:
    try:
        t = int(v)
    except (TypeError, ValueError):
        return ""
    if t <= 0:
        return ""
    try:
        return datetime.fromtimestamp(t, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


_AUTH_VALUE = {0: "denied", 1: "unknown", 2: "allowed", 3: "limited"}
_AUTH_REASON = {
    0: "unset", 1: "error", 2: "user consent", 3: "user set",
    4: "system set", 5: "service policy", 6: "MDM policy",
    7: "override policy", 8: "missing usage string", 9: "prompt timeout",
    10: "preflight unknown", 11: "entitled", 12: "app type policy",
}


@dataclass
class Grant:
    scope: str                # system | user
    service_raw: str
    service: str
    client: str
    client_type: str          # bundle-id | path
    decision: str
    auth_reason: str
    indirect_object: str
    last_modified: str
    from_profile: bool
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "scope": self.scope, "service": self.service,
            "service_raw": self.service_raw, "client": self.client,
            "client_type": self.client_type, "decision": self.decision,
            "auth_reason": self.auth_reason,
            "indirect_object": self.indirect_object,
            "last_modified": self.last_modified,
            "from_profile": "yes" if self.from_profile else "",
            "source": self.source, "notable": ";".join(self.notable),
        }


def parse(path: str, scope: str = "") -> list[Grant]:
    out: list[Grant] = []
    with connect(path) as con:
        con.row_factory = sqlite3.Row
        try:
            cols = {r[1] for r in con.execute("PRAGMA table_info(access)")}
        except sqlite3.Error:
            return out
        if not cols:
            return out
        try:
            rows = con.execute("SELECT * FROM access").fetchall()
        except sqlite3.Error:
            return out
        for r in rows:
            g = dict(r)
            if "auth_value" in cols:
                decision = _AUTH_VALUE.get(g.get("auth_value"),
                                           str(g.get("auth_value")))
            elif "allowed" in cols:
                decision = "allowed" if g.get("allowed") else "denied"
            else:
                decision = "?"
            svc = str(g.get("service") or "")
            ct = g.get("client_type")
            reason = g.get("auth_reason")
            flags_v = g.get("flags") or 0
            out.append(_finish(Grant(
                scope=scope or _scope_of(path),
                service_raw=svc, service=SERVICES.get(svc, svc),
                client=str(g.get("client") or ""),
                client_type="path" if ct == 1 else "bundle-id",
                decision=decision,
                auth_reason=_AUTH_REASON.get(reason,
                                             str(reason) if reason is not None
                                             else ""),
                indirect_object=str(g.get("indirect_object_identifier")
                                    or "") if g.get(
                    "indirect_object_identifier") not in (None, "UNUSED")
                else "",
                last_modified=_utc(g.get("last_modified")),
                from_profile=bool(reason == 6 or (flags_v and flags_v & 0x10)),
                source=path)))
    out.sort(key=lambda x: (x.scope, x.service, x.client))
    return out


def _scope_of(path: str) -> str:
    return "user" if ("Users" in path or path.startswith("~") or
                      "/home/" in path.replace("\\", "/")) else "system"


def _finish(g: Grant) -> Grant:
    g.notable = _flags.flag(g)
    return g
