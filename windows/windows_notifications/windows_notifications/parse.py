"""Read Notification + NotificationHandler from wpndatabase.db."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree as ET

from windows_notifications import flags as _flags
from windows_notifications.dbopen import connect

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(v) -> str:
    try:
        t = int(v)
    except (TypeError, ValueError):
        return ""
    if t <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=t / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


_TAG_TEXT = re.compile(r"<text[^>]*>(.*?)</text>", re.S | re.I)


def _payload_text(payload) -> str:
    if not payload:
        return ""
    if isinstance(payload, (bytes, bytearray)):
        payload = bytes(payload).decode("utf-8", "replace")
    txt = str(payload)
    parts: list[str] = []
    try:
        root = ET.fromstring(txt)
        for el in root.iter():
            tag = el.tag.split("}")[-1].lower()
            if tag in ("text", "subtitle", "title") and el.text:
                parts.append(el.text.strip())
    except ET.ParseError:
        parts = [m.group(1).strip() for m in _TAG_TEXT.finditer(txt)]
    parts = [re.sub(r"\s+", " ", p) for p in parts if p]
    return " | ".join(dict.fromkeys(parts))[:1000]


@dataclass
class Notification:
    app: str
    handler_type: str
    ntype: str
    text: str
    tag: str
    group: str
    arrival: str
    expiry: str
    boot_id: str
    payload_type: str
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {"app": self.app, "handler_type": self.handler_type,
                "type": self.ntype, "text": self.text, "tag": self.tag,
                "group": self.group, "arrival": self.arrival,
                "expiry": self.expiry, "boot_id": self.boot_id,
                "payload_type": self.payload_type, "source": self.source,
                "notable": ";".join(self.notable)}


_NTYPE = {1: "toast", 2: "tile", 3: "badge", 4: "raw"}


def parse(path: str) -> list[Notification]:
    out: list[Notification] = []
    with connect(path) as con:
        con.row_factory = sqlite3.Row
        handlers: dict = {}
        try:
            for r in con.execute("SELECT * FROM NotificationHandler"):
                handlers[r["RecordId"]] = (
                    r["PrimaryId"] if "PrimaryId" in r.keys() else "",
                    r["HandlerType"] if "HandlerType" in r.keys() else "")
        except sqlite3.Error:
            pass
        try:
            cur = con.execute("SELECT * FROM Notification")
        except sqlite3.Error:
            return out
        cols = [d[0] for d in cur.description]
        for raw in cur.fetchall():
            r = dict(zip(cols, raw))
            hid = r.get("HandlerId")
            app, htype = handlers.get(hid, ("", ""))
            ntype = r.get("Type")
            if isinstance(ntype, int):
                ntype = _NTYPE.get(ntype, str(ntype))
            elif not ntype:
                ntype = ""
            n = Notification(
                app=str(app or f"handler#{hid}"),
                handler_type=str(htype or ""),
                ntype=str(ntype),
                text=_payload_text(r.get("Payload")),
                tag=str(r.get("Tag") or ""),
                group=str(r.get("Group") or ""),
                arrival=_ft(r.get("ArrivalTime")),
                expiry=_ft(r.get("ExpiryTime")),
                boot_id=str(r.get("BootId") or ""),
                payload_type=str(r.get("PayloadType") or ""),
                source=path)
            n.notable = _flags.flag(n)
            out.append(n)
    out.sort(key=lambda n: (n.arrival or "", n.app))
    return out
