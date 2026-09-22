"""Recognize message objects by their documented public Web API shape.

Slack's and Discord's message JSON formats are published, stable API
contracts - matching on them is different from guessing at either
client's undocumented internal LevelDB value encoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class Message:
    app: str
    conversation: str
    sender: str
    timestamp: str
    text: str


def _slack_ts(ts) -> str:
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError, OverflowError):
        return str(ts)


def match_slack(obj: dict) -> Message | None:
    if not isinstance(obj, dict):
        return None
    if obj.get("type") != "message":
        return None
    text = obj.get("text")
    ts = obj.get("ts")
    if not isinstance(text, str) or not isinstance(ts, str):
        return None
    sender = obj.get("user") or obj.get("bot_id") or obj.get("username") \
        or ""
    if not isinstance(sender, str):
        return None
    conversation = obj.get("channel", "")
    return Message("slack", str(conversation), sender, _slack_ts(ts), text)


def match_discord(obj: dict) -> Message | None:
    if not isinstance(obj, dict):
        return None
    content = obj.get("content")
    author = obj.get("author")
    timestamp = obj.get("timestamp")
    msg_id = obj.get("id")
    if not (isinstance(content, str) and isinstance(author, dict)
           and isinstance(timestamp, str) and isinstance(msg_id, (str, int))):
        return None
    sender = author.get("username") or author.get("id") or ""
    if not isinstance(sender, str):
        return None
    conversation = obj.get("channel_id", "")
    return Message("discord", str(conversation), sender, timestamp, content)


_MATCHERS = (match_slack, match_discord)


def match_any(obj: dict) -> Message | None:
    for m in _MATCHERS:
        result = m(obj)
        if result is not None:
            return result
    return None
