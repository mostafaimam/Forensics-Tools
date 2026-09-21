from __future__ import annotations

import json

import pytest

import _synth as S
from _snappy_encode import compress_literal_only

from browser_localstorage import crc32c
from browser_localstorage.varint import decode as varint_decode, \
    encode as varint_encode
from browser_localstorage.snappy import decompress, SnappyError
from browser_localstorage.leveldblog import read as read_log
from browser_localstorage.sstable import read as read_sstable
from browser_localstorage.localstorage import decode as ls_decode
from browser_localstorage.collect import collect
from browser_localstorage.cli import main


def test_varint_roundtrip():
    for n in (0, 1, 127, 128, 300, 2**32, 2**63 - 1):
        enc = varint_encode(n)
        got, pos = varint_decode(enc + b"\x00extra", 0)
        assert got == n
        assert pos == len(enc)


def test_crc32c_known_vector():
    # RFC 3720 test vector: CRC32C("123456789") = 0xE3069283
    assert crc32c.crc32c(b"123456789") == 0xE3069283


def test_crc32c_mask_roundtrip():
    c = crc32c.crc32c(b"hello world")
    m = crc32c.mask(c)
    assert m != c
    assert crc32c.unmask(m) == c


def test_snappy_literal_roundtrip():
    data = b"the quick brown fox jumps over the lazy dog" * 5
    compressed = compress_literal_only(data)
    assert decompress(compressed) == data


def test_snappy_bad_offset_rejected():
    # varint length=1, then a copy tag claiming offset beyond output so far
    payload = varint_encode(1) + bytes([0b00000101, 0xFF])  # kind=1, offset hi bits set high
    with pytest.raises(SnappyError):
        decompress(payload)


def test_log_value_and_deletion(tmp_path):
    p = tmp_path / "000003.log"
    S.write_log(p, [
        (100, [("value", b"key-a", b"value-a"),
              ("value", b"key-b", b"value-b")]),
        (102, [("deletion", b"key-a", None)]),
    ])
    recs = list(read_log(str(p)))
    assert len(recs) == 3
    a1 = next(r for r in recs if r.sequence == 100 and r.key == b"key-a")
    assert not a1.deleted and a1.value == b"value-a"
    b1 = next(r for r in recs if r.key == b"key-b")
    assert b1.sequence == 101 and b1.value == b"value-b"
    tombstone = next(r for r in recs if r.sequence == 102)
    assert tombstone.deleted and tombstone.key == b"key-a"


def test_log_rejects_bad_crc(tmp_path):
    p = tmp_path / "000004.log"
    S.write_log(p, [(1, [("value", b"k", b"v")])])
    data = bytearray(p.read_bytes())
    data[0] ^= 0xFF  # corrupt the stored crc
    p.write_bytes(bytes(data))
    assert list(read_log(str(p))) == []


def test_sstable_uncompressed(tmp_path):
    p = tmp_path / "000005.ldb"
    S.write_sstable(p, [
        (b"aaa", 5, False, b"value-aaa"),
        (b"bbb", 6, True, b""),
    ])
    recs = list(read_sstable(str(p)))
    assert len(recs) == 2
    aaa = next(r for r in recs if r.key == b"aaa")
    assert aaa.sequence == 5 and not aaa.deleted and aaa.value == b"value-aaa"
    bbb = next(r for r in recs if r.key == b"bbb")
    assert bbb.sequence == 6 and bbb.deleted


def test_sstable_snappy_compressed(tmp_path):
    p = tmp_path / "000006.ldb"
    records = [(f"key{i}".encode(), 10 + i, False,
               (f"value-{i}-" * 8).encode()) for i in range(20)]
    S.write_sstable(p, records, compress=True)
    recs = list(read_sstable(str(p)))
    assert len(recs) == 20
    assert {r.key for r in recs} == {f"key{i}".encode() for i in range(20)}


def test_localstorage_key_schema():
    key = S.local_storage_key("https://example.com", "theme")
    value = S.local_storage_value("dark-mode", utf16=True)
    entry = ls_decode(key, value)
    assert entry.matched_schema
    assert entry.origin == "https://example.com"
    assert entry.key == "theme"
    assert entry.value == "dark-mode"


def test_localstorage_latin1_value():
    key = S.local_storage_key("https://example.com", "flag")
    value = S.local_storage_value("plain", utf16=False)
    entry = ls_decode(key, value)
    assert entry.value == "plain"


def test_localstorage_unmatched_key_falls_back():
    entry = ls_decode(b"VERSION", bytes([0]) + "1".encode("utf-16-le"))
    assert not entry.matched_schema
    assert entry.value == "1"


def test_collect_local_storage_dir(tmp_path):
    d = tmp_path / "Local Storage" / "leveldb"
    d.mkdir(parents=True)
    S.write_log(d / "000001.log", [
        (1, [("value", S.local_storage_key("https://a.example", "k1"),
             S.local_storage_value("v1"))]),
    ])
    res = collect([str(tmp_path)])
    assert not res.warnings
    row = next(r for r in res.rows if r["key"] == "k1")
    assert row["store_kind"] == "local_storage"
    assert row["origin"] == "https://a.example"
    assert row["value"] == "v1"


def test_collect_indexeddb_dir_raw(tmp_path):
    d = tmp_path / "IndexedDB" / "https_a.example_0.indexeddb.leveldb"
    d.mkdir(parents=True)
    S.write_log(d / "000001.log", [
        (1, [("value", b"raw-key", b"raw-value")]),
    ])
    res = collect([str(tmp_path)])
    row = next(r for r in res.rows if r["key"] == "raw-key")
    assert row["store_kind"] == "indexeddb"
    assert row["origin"] == ""
    assert row["value"] == "raw-value"


def test_collect_no_store_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_deleted_history_recovered(tmp_path):
    d = tmp_path / "Local Storage" / "leveldb"
    d.mkdir(parents=True)
    key = S.local_storage_key("https://a.example", "session")
    S.write_log(d / "000001.log", [
        (1, [("value", key, S.local_storage_value("token-123"))]),
        (2, [("deletion", key, None)]),
    ])
    res = collect([str(tmp_path)])
    live = [r for r in res.rows if not r["deleted"]]
    tombstones = [r for r in res.rows if r["deleted"]]
    assert live[0]["value"] == "token-123"
    assert tombstones and tombstones[0]["key"] == "session"


def test_cli_csv_json(tmp_path):
    d = tmp_path / "Local Storage" / "leveldb"
    d.mkdir(parents=True)
    S.write_log(d / "000001.log", [
        (1, [("value", S.local_storage_key("https://a.example", "k"),
             S.local_storage_value("v"))]),
    ])
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p),
              "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_origin_filter(tmp_path):
    d = tmp_path / "Local Storage" / "leveldb"
    d.mkdir(parents=True)
    S.write_log(d / "000001.log", [
        (1, [("value", S.local_storage_key("https://a.example", "k"),
             S.local_storage_value("v")),
            ("value", S.local_storage_key("https://b.example", "k"),
             S.local_storage_value("v"))]),
    ])
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--origin", "a.example", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all("a.example" in r["origin"] for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from browser_localstorage.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
