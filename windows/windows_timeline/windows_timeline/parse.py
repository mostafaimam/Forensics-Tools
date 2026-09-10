"""Read the Activity / ActivityOperation tables from ActivitiesCache.db."""

from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

from windows_timeline import flags as _flags
from windows_timeline.dbopen import connect

ACTIVITY_TYPES = {
    2: "notification", 3: "mobile-notification", 5: "open-app-or-file",
    6: "in-app", 10: "clipboard", 11: "copy-paste", 12: "system",
    15: "quiet-hours", 16: "notification",
}


def _utc(epoch) -> str:
    try:
        e = int(epoch)
        if e <= 0:
            return ""
        if e > 10_000_000_000:            # milliseconds
            e //= 1000
        return datetime.fromtimestamp(e, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


@dataclass
class Activity:
    activity_id: str
    activity_type: str
    app: str
    app_raw: str
    display_text: str
    content_uri: str
    description: str
    start: str
    end: str
    last_modified: str
    expires: str
    duration_s: int
    is_local_only: bool
    created_in_cloud: bool
    clipboard_text: str
    from_operation: bool
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "activity_id": self.activity_id,
            "activity_type": self.activity_type,
            "app": self.app, "app_raw": self.app_raw,
            "display_text": self.display_text, "content_uri": self.content_uri,
            "description": self.description, "start": self.start,
            "end": self.end, "last_modified": self.last_modified,
            "expires": self.expires, "duration_s": self.duration_s,
            "is_local_only": "yes" if self.is_local_only else "",
            "created_in_cloud": "yes" if self.created_in_cloud else "",
            "clipboard_text": self.clipboard_text,
            "from_operation": "yes" if self.from_operation else "",
            "source": self.source, "notable": ";".join(self.notable),
        }


def _resolve_app(appid_raw) -> tuple[str, str]:
    if isinstance(appid_raw, (bytes, bytearray)):
        appid_raw = bytes(appid_raw).decode("utf-8", "replace")
    raw = str(appid_raw or "")
    try:
        arr = json.loads(raw)
    except (ValueError, TypeError):
        return raw, raw
    win32 = ""
    packaged = ""
    for item in arr if isinstance(arr, list) else []:
        app = item.get("application", "")
        plat = item.get("platform", "")
        if plat in ("windows_win32", "x_exe_path") and "\\" in app:
            win32 = app
        elif plat in ("packageId", "windows_universal", "afs_crossplatform"):
            packaged = packaged or app
    return (win32 or packaged or raw), raw


def _clipboard(blob) -> str:
    if not blob:
        return ""
    try:
        arr = json.loads(blob if isinstance(blob, str)
                         else bytes(blob).decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return ""
    out = []
    for item in arr if isinstance(arr, list) else []:
        content = item.get("content", "")
        try:
            txt = base64.b64decode(content).decode("utf-16-le", "replace") \
                .rstrip("\x00")
            if not txt.isprintable():
                txt = base64.b64decode(content).decode("utf-8", "replace")
        except (ValueError, TypeError):
            txt = content
        if txt.strip():
            out.append(txt.strip())
    return " | ".join(out)[:2000]


def _payload(raw) -> tuple[str, str, str]:
    try:
        d = json.loads(raw if isinstance(raw, str)
                       else bytes(raw).decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return "", "", ""
    if not isinstance(d, dict):
        return "", "", ""
    return (str(d.get("displayText", "") or d.get("appDisplayName", "")),
            str(d.get("contentUri", "") or d.get("1", "")),
            str(d.get("description", "")))


def _rows(con, table: str, from_op: bool, source: str):
    try:
        cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return
    if not cols:
        return
    q = f"SELECT * FROM {table}"
    try:
        cur = con.execute(q)
    except sqlite3.Error:
        return
    names = [d[0] for d in cur.description]
    for raw in cur.fetchall():
        r = dict(zip(names, raw))
        app, app_raw = _resolve_app(r.get("AppId"))
        disp, uri, desc = _payload(r.get("Payload"))
        start = _utc(r.get("StartTime"))
        end = _utc(r.get("EndTime"))
        dur = 0
        try:
            if r.get("StartTime") and r.get("EndTime"):
                dur = max(0, int(r["EndTime"]) - int(r["StartTime"]))
        except (TypeError, ValueError):
            dur = 0
        aid = r.get("Id")
        if isinstance(aid, (bytes, bytearray)):
            aid = bytes(aid).hex()
        yield Activity(
            activity_id=str(aid or ""),
            activity_type=ACTIVITY_TYPES.get(r.get("ActivityType"),
                                             str(r.get("ActivityType"))),
            app=app, app_raw=app_raw, display_text=disp, content_uri=uri,
            description=desc, start=start, end=end,
            last_modified=_utc(r.get("LastModifiedTime")),
            expires=_utc(r.get("ExpirationTime")), duration_s=dur,
            is_local_only=bool(r.get("IsLocalOnly")),
            created_in_cloud=bool(r.get("CreatedInCloud")),
            clipboard_text=_clipboard(r.get("ClipboardPayload")),
            from_operation=from_op, source=source)


def parse(path: str) -> list[Activity]:
    acts: list[Activity] = []
    with connect(path) as con:
        for a in _rows(con, "Activity", False, path):
            acts.append(a)
        for a in _rows(con, "ActivityOperation", True, path):
            acts.append(a)
    for a in acts:
        a.notable = _flags.flag(a)
    acts.sort(key=lambda a: (a.start or a.last_modified or "",
                             a.activity_type))
    return acts
