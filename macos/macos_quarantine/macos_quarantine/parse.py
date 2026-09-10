"""Read the LSQuarantineEvent table."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from macos_quarantine import flags as _flags
from macos_quarantine.dbopen import connect

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

_TYPE = {0: "web download", 1: "email attachment", 2: "other download",
         5: "attachment"}


def _mac_time(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return ""
    if f <= 0:
        return ""
    if f > 3_000_000_000:                 # already a Unix timestamp
        f -= _MAC_EPOCH.timestamp()
    try:
        return (_MAC_EPOCH + timedelta(seconds=f)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class Event:
    identifier: str
    timestamp: str
    agent_bundle: str
    agent_name: str
    data_url: str
    origin_url: str
    origin_title: str
    sender_name: str
    sender_address: str
    event_type: str
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "timestamp": self.timestamp, "agent_name": self.agent_name,
            "agent_bundle": self.agent_bundle, "data_url": self.data_url,
            "origin_url": self.origin_url, "origin_title": self.origin_title,
            "sender_name": self.sender_name,
            "sender_address": self.sender_address,
            "event_type": self.event_type, "identifier": self.identifier,
            "source": self.source, "notable": ";".join(self.notable),
        }


_COLS = {
    "identifier": "LSQuarantineEventIdentifier",
    "timestamp": "LSQuarantineTimeStamp",
    "agent_bundle": "LSQuarantineAgentBundleIdentifier",
    "agent_name": "LSQuarantineAgentName",
    "data_url": "LSQuarantineDataURLString",
    "origin_url": "LSQuarantineOriginURLString",
    "origin_title": "LSQuarantineOriginTitle",
    "sender_name": "LSQuarantineSenderName",
    "sender_address": "LSQuarantineSenderAddress",
    "event_type": "LSQuarantineTypeNumber",
}


def parse(path: str) -> list[Event]:
    out: list[Event] = []
    with connect(path) as con:
        con.row_factory = sqlite3.Row
        try:
            have = {r[1] for r in con.execute(
                "PRAGMA table_info(LSQuarantineEvent)")}
        except sqlite3.Error:
            return out
        if not have:
            return out
        sel = ", ".join(f'"{c}"' for c in _COLS.values() if c in have)
        try:
            rows = con.execute(
                f"SELECT {sel} FROM LSQuarantineEvent "
                f'ORDER BY "LSQuarantineTimeStamp"').fetchall()
        except sqlite3.Error:
            return out
        for r in rows:
            g = dict(r)
            et = g.get("LSQuarantineTypeNumber")
            e = Event(
                identifier=str(g.get("LSQuarantineEventIdentifier") or ""),
                timestamp=_mac_time(g.get("LSQuarantineTimeStamp")),
                agent_bundle=str(g.get("LSQuarantineAgentBundleIdentifier")
                                 or ""),
                agent_name=str(g.get("LSQuarantineAgentName") or ""),
                data_url=str(g.get("LSQuarantineDataURLString") or ""),
                origin_url=str(g.get("LSQuarantineOriginURLString") or ""),
                origin_title=str(g.get("LSQuarantineOriginTitle") or ""),
                sender_name=str(g.get("LSQuarantineSenderName") or ""),
                sender_address=str(g.get("LSQuarantineSenderAddress") or ""),
                event_type=_TYPE.get(et, str(et) if et is not None else ""),
                source=path)
            e.notable = _flags.flag(e)
            out.append(e)
    out.sort(key=lambda e: e.timestamp or "")
    return out
