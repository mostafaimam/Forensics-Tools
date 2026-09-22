from __future__ import annotations

import json
from datetime import datetime

import pytest

import _synth as S

from mobile_appcommon.sniff import guess_format
from mobile_appcommon.protobuf import decode_top, to_jsonable
from mobile_appcommon.collect import decode_blob, decode_file
from mobile_appcommon.cli import main


def test_sniff_plist():
    import plistlib
    blob = plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY)
    assert guess_format(blob) == "plist"


def test_sniff_sqlite():
    assert guess_format(b"SQLite format 3\x00rest") == "sqlite"


def test_sniff_text():
    assert guess_format(b'{"a": 1}') == "text"


def test_sniff_protobuf_fallback():
    assert guess_format(b"\x08\x01\x12\x02hi") == "protobuf"


def test_decode_simple_varint_and_string():
    blob = S.varint_field(1, 42) + S.string_field(2, "hello")
    fields = decode_top(blob)
    assert fields is not None
    assert fields[0].number == 1 and fields[0].kind == "varint" \
        and fields[0].value == 42
    assert fields[1].number == 2 and fields[1].kind == "string" \
        and fields[1].value == "hello"


def test_decode_nested_message():
    inner = S.varint_field(1, 7) + S.string_field(2, "nested")
    outer = S.message_field(1, inner) + S.varint_field(2, 99)
    fields = decode_top(outer)
    assert fields[0].kind == "message"
    assert fields[0].value[0].value == 7
    assert fields[0].value[1].value == "nested"
    assert fields[1].value == 99


def test_decode_bytes_not_text():
    blob = S.bytes_field(1, bytes(range(256))[:32])
    fields = decode_top(blob)
    assert fields[0].kind == "bytes"


def test_decode_garbage_returns_none():
    assert decode_top(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff") is None


def test_decode_empty_returns_empty_list():
    assert decode_top(b"") == []


def test_to_jsonable_roundtrips_through_json():
    blob = S.varint_field(1, 5) + S.string_field(2, "x")
    fields = decode_top(blob)
    j = to_jsonable(fields)
    text = json.dumps(j)
    assert "\"value\": 5" in text
    assert "\"x\"" in text


def test_collect_blob_protobuf(tmp_path):
    blob = S.varint_field(1, 123) + S.string_field(2, "field-two")
    p = tmp_path / "cache.blob"
    p.write_bytes(blob)
    res = decode_file(str(p))
    assert res.fmt == "protobuf"
    assert not res.warnings
    paths = {r["path"]: r["value"] for r in res.rows}
    assert paths["1"] == "123"
    assert paths["2"] == "field-two"


def test_collect_blob_nested_flattened(tmp_path):
    inner = S.varint_field(1, 7)
    outer = S.message_field(3, inner)
    p = tmp_path / "cache.blob"
    p.write_bytes(outer)
    res = decode_file(str(p))
    paths = [r["path"] for r in res.rows]
    assert "3" in paths
    assert "3.1" in paths


def test_collect_plist(tmp_path):
    p = tmp_path / "info.plist"
    S.build_plist_file(p, {"Name": "Example", "Count": 3})
    res = decode_file(str(p))
    assert res.fmt == "plist"
    values = {r["path"]: r["value"] for r in res.rows}
    assert values["Name"] == "Example"
    assert values["Count"] == "3"


def test_collect_sqlite_warns(tmp_path):
    p = tmp_path / "db.sqlite"
    p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    res = decode_file(str(p))
    assert res.fmt == "sqlite"
    assert not res.rows
    assert res.warnings


def test_collect_unrecognised_warns():
    res = decode_blob(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
    assert not res.rows
    assert res.warnings


def test_cli_hex(tmp_path):
    blob = S.varint_field(1, 9)
    hexstr = blob.hex()
    js_p = tmp_path / "out.json"
    rc = main(["--hex", hexstr, "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows[0]["value"] == "9"


def test_cli_file_csv_json(tmp_path):
    blob = S.varint_field(1, 1) + S.string_field(2, "abc")
    p = tmp_path / "b.blob"
    p.write_bytes(blob)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_bad_hex():
    rc = main(["--hex", "not-hex"])
    assert rc == 2


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from mobile_appcommon.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
