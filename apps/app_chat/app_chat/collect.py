"""Tie app discovery, LevelDB reading, and message recognition together."""

from __future__ import annotations

from dataclasses import dataclass, field

from app_chat.discover import find_app_dirs
from app_chat.jsoncarve import find_json_objects
from app_chat.messageshapes import match_any
from app_chat.store import read_dir

COLUMNS = ["kind", "app", "conversation", "sender", "timestamp", "text",
          "deleted", "source"]

_MESSAGE_APPS = ("slack", "discord")
_RAW_APPS = ("teams",)


def _decode_text(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8", "utf-16-le"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
        if text and printable / len(text) > 0.9:
            return text
    return ""


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _collect_messages(app: str, target: str) -> list[dict]:
    rows = []
    for d in find_app_dirs(target, app):
        for rec in read_dir(d):
            for obj in find_json_objects(rec.value):
                msg = match_any(obj)
                if msg is None or msg.app != app:
                    continue
                rows.append({
                    "kind": "message", "app": msg.app,
                    "conversation": msg.conversation, "sender": msg.sender,
                    "timestamp": msg.timestamp, "text": msg.text,
                    "deleted": rec.deleted, "source": str(d),
                })
    return rows


def _collect_raw(app: str, target: str) -> list[dict]:
    rows = []
    for d in find_app_dirs(target, app):
        for rec in read_dir(d):
            text = _decode_text(rec.value)
            if not (10 <= len(text) <= 5000):
                continue
            rows.append({
                "kind": "raw", "app": app, "conversation": "", "sender": "",
                "timestamp": "", "text": text, "deleted": rec.deleted,
                "source": str(d),
            })
    return rows


def collect(target: str, *, apps: list[str] | None = None) -> Result:
    res = Result()
    wanted = apps or list(_MESSAGE_APPS + _RAW_APPS)
    for app in wanted:
        if app in _MESSAGE_APPS:
            res.rows.extend(_collect_messages(app, target))
        elif app in _RAW_APPS:
            res.rows.extend(_collect_raw(app, target))
    if not res.rows:
        res.warnings.append("no recognisable chat data found (Slack/"
                            "Discord message shapes or Teams LevelDB "
                            "directories)")
    return res
