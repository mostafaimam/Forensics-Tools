"""Build real LevelDB .log files (WAL) for chat-app test fixtures."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from app_chat import crc32c
from app_chat.varint import encode as v

_TYPE_FULL = 1
_TAG_VALUE, _TAG_DELETION = 1, 0


def _crc_for(rtype: int, payload: bytes) -> int:
    return crc32c.mask(crc32c.crc32c(payload, crc32c.crc32c(bytes([rtype]))))


def write_log(path: Path, batches: list[tuple[int, list[tuple[str, bytes,
                                                              bytes | None]]]]) -> None:
    """batches: [(sequence, [(tag, key, value_or_none), ...]), ...]"""
    out = bytearray()
    for seq, entries in batches:
        body = bytearray()
        for tag, key, value in entries:
            if tag == "value":
                body += bytes([_TAG_VALUE]) + v(len(key)) + key + \
                    v(len(value)) + value
            else:
                body += bytes([_TAG_DELETION]) + v(len(key)) + key
        record = struct.pack("<Q", seq) + struct.pack("<I", len(entries)) \
            + bytes(body)
        crc = _crc_for(_TYPE_FULL, record)
        out += struct.pack("<I", crc) + struct.pack("<H", len(record)) + \
            bytes([_TYPE_FULL]) + record
    path.write_bytes(bytes(out))


def slack_message_json(text="hello team", user="U123", ts="1735689600.000100",
                       channel="C999"):
    return json.dumps({"type": "message", "text": text, "user": user,
                      "ts": ts, "channel": channel}).encode()


def discord_message_json(content="gg wp", username="alice",
                         timestamp="2026-01-01T00:00:00.000000+00:00",
                         channel_id="555", msg_id="999"):
    return json.dumps({"id": msg_id, "content": content,
                      "author": {"id": "1", "username": username},
                      "timestamp": timestamp,
                      "channel_id": channel_id}).encode()


def build_slack_tree(root: Path, *, deleted=False) -> Path:
    d = root / "Slack" / "Local Storage" / "leveldb"
    d.mkdir(parents=True)
    key = b"_https://app.slack.com\x00recent-message"
    batches = [(1, [("value", key, slack_message_json())])]
    if deleted:
        batches.append((2, [("deletion", key, None)]))
    write_log(d / "000003.log", batches)
    return root


def build_discord_tree(root: Path) -> Path:
    d = root / "discord" / "Local Storage" / "leveldb"
    d.mkdir(parents=True)
    key = b"_https://discord.com\x00cached-message"
    write_log(d / "000003.log", [
        (1, [("value", key, discord_message_json())]),
    ])
    return root


def build_teams_tree(root: Path) -> Path:
    d = root / "Microsoft" / "Teams" / "Local Storage" / "leveldb"
    d.mkdir(parents=True)
    write_log(d / "000003.log", [
        (1, [("value", b"conversation-cache",
             b"a plausible cached conversation snippet text")]),
    ])
    return root
