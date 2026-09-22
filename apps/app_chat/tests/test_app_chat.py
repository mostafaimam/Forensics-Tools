from __future__ import annotations

import json

import pytest

import _synth as S

from app_chat.jsoncarve import find_json_objects
from app_chat.messageshapes import match_slack, match_discord, match_any
from app_chat.collect import collect
from app_chat.cli import main


def test_find_json_objects_in_plain_json():
    data = json.dumps({"a": 1, "b": "text"}).encode()
    objs = find_json_objects(data)
    assert objs == [{"a": 1, "b": "text"}]


def test_find_json_objects_embedded_in_noise():
    data = b"\x00\x01prefix garbage " + json.dumps({"x": "y"}).encode() + \
        b" trailing \xff\xfe noise"
    objs = find_json_objects(data)
    assert {"x": "y"} in objs


def test_find_json_objects_nested():
    data = json.dumps({"outer": {"inner": 1}}).encode()
    objs = find_json_objects(data)
    assert any(o.get("outer", {}).get("inner") == 1 for o in objs)


def test_match_slack_message():
    obj = json.loads(S.slack_message_json(text="hi there"))
    msg = match_slack(obj)
    assert msg is not None
    assert msg.text == "hi there"
    assert msg.app == "slack"
    assert msg.timestamp.startswith("2025-") or msg.timestamp.startswith(
        "2026-")


def test_match_slack_rejects_non_message():
    assert match_slack({"type": "presence_change", "user": "U1"}) is None


def test_match_discord_message():
    obj = json.loads(S.discord_message_json(content="gg"))
    msg = match_discord(obj)
    assert msg is not None
    assert msg.text == "gg"
    assert msg.app == "discord"
    assert msg.sender == "alice"


def test_match_discord_rejects_incomplete():
    assert match_discord({"content": "hi"}) is None


def test_match_any_tries_both():
    slack_obj = json.loads(S.slack_message_json())
    assert match_any(slack_obj).app == "slack"
    discord_obj = json.loads(S.discord_message_json())
    assert match_any(discord_obj).app == "discord"


def test_collect_slack_messages(tmp_path):
    S.build_slack_tree(tmp_path)
    res = collect(str(tmp_path), apps=["slack"])
    assert not res.warnings
    assert len(res.rows) == 1
    assert res.rows[0]["kind"] == "message"
    assert res.rows[0]["app"] == "slack"
    assert res.rows[0]["text"] == "hello team"


def test_collect_discord_messages(tmp_path):
    S.build_discord_tree(tmp_path)
    res = collect(str(tmp_path), apps=["discord"])
    assert len(res.rows) == 1
    assert res.rows[0]["app"] == "discord"
    assert res.rows[0]["sender"] == "alice"


def test_message_content_survives_a_later_deletion(tmp_path):
    # LevelDB is append-only: the original write record (holding the
    # actual message JSON) is a separate, earlier record from whatever
    # later deletes the key. The deletion record itself carries no
    # value, so it never becomes a "message" row - but the original
    # content is still recovered from its own record, exactly as
    # browser_localstorage recovers a value that was later deleted.
    S.build_slack_tree(tmp_path, deleted=True)
    res = collect(str(tmp_path), apps=["slack"])
    assert len(res.rows) == 1
    assert res.rows[0]["text"] == "hello team"


def test_collect_teams_raw(tmp_path):
    S.build_teams_tree(tmp_path)
    res = collect(str(tmp_path), apps=["teams"])
    assert res.rows
    assert res.rows[0]["kind"] == "raw"
    assert res.rows[0]["app"] == "teams"
    assert "cached conversation" in res.rows[0]["text"]


def test_collect_no_apps_found_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect(str(empty))
    assert not res.rows
    assert res.warnings


def test_collect_all_apps_by_default(tmp_path):
    S.build_slack_tree(tmp_path)
    S.build_discord_tree(tmp_path)
    res = collect(str(tmp_path))
    apps = {r["app"] for r in res.rows}
    assert "slack" in apps
    assert "discord" in apps


def test_cli_csv_json(tmp_path):
    S.build_slack_tree(tmp_path)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p),
              "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_app_filter(tmp_path):
    S.build_slack_tree(tmp_path)
    S.build_discord_tree(tmp_path)
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--app", "discord", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["app"] == "discord" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from app_chat.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
