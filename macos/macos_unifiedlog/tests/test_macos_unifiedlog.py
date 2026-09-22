from __future__ import annotations

import json

import pytest

import _synth as S

from macos_unifiedlog.lz4block import Lz4Error, decompress_block
from macos_unifiedlog.tracev3 import (carve_strings, decompress_chunkset,
                                      iter_chunks)
from macos_unifiedlog.collect import collect
from macos_unifiedlog.cli import main


def test_lz4_literal_only_roundtrip():
    data = b"hello unified log world, this is a literal run" * 2
    block = S.lz4_literal_only_block(data)
    assert decompress_block(block) == data


def test_lz4_match_roundtrip():
    # "abcdabcd": literal "abcd", then a 4-byte match 4 bytes back
    block = S.lz4_block_with_match(b"abcd", 4, 4)
    assert decompress_block(block) == b"abcdabcd"


def test_lz4_long_match_run():
    # a longer repeat, exercising the byte-run length extension and
    # LZ4's required overlapping self-referential copy (offset < length)
    literal = b"prefix-"
    block = S.lz4_block_with_match(literal, len(literal), 40)
    out = decompress_block(block)
    assert len(out) == len(literal) + 40
    expected_tail = (literal * 7)[:40]  # "prefix-" repeating
    assert out[len(literal):] == expected_tail


def test_lz4_invalid_offset_rejected():
    # a match offset larger than anything decoded so far
    bad = bytes([0x04]) + b"ab" + b"\xff\xff"
    with pytest.raises(Lz4Error):
        decompress_block(bad)


def test_iter_chunks_recovers_tag_and_payload():
    payload = b"hello-chunk-payload"
    data = S.chunk_bytes(0x1000, payload)
    chunks = list(iter_chunks(data))
    assert len(chunks) == 1
    assert chunks[0].tag == 0x1000
    assert chunks[0].tag_name == "header"
    assert chunks[0].payload == payload


def test_iter_chunks_multiple_with_alignment():
    data = S.chunk_bytes(0x1000, b"abc") + S.chunk_bytes(0x600B, b"defgh")
    chunks = list(iter_chunks(data))
    assert [c.tag_name for c in chunks] == ["header", "catalog"]
    assert chunks[1].payload == b"defgh"


def test_decompress_chunkset_raw_passthrough():
    nested = S.chunk_bytes(0x6001, b"firehose-payload")
    payload = b"bv4-" + (0).to_bytes(4, "little") + nested
    result = decompress_chunkset(payload)
    assert result is not None
    chunks = list(iter_chunks(result))
    assert chunks[0].tag_name == "firehose"
    assert chunks[0].payload == b"firehose-payload"


def test_decompress_chunkset_compressed():
    nested = S.chunk_bytes(0x6001, b"a firehose payload long enough to "
                          b"be worth compressing, repeated text " * 2)
    block = S.lz4_literal_only_block(nested)
    payload = b"bv41" + len(block).to_bytes(4, "little") + block
    result = decompress_chunkset(payload)
    assert result is not None
    assert result == nested


def test_decompress_chunkset_garbage_returns_none():
    assert decompress_chunkset(b"\xff" * 64) is None


def test_carve_strings_ascii():
    data = b"\x00\x01com.apple.something\x00\x00shortlog message here\x02"
    found = carve_strings(data, min_length=6)
    assert any("com.apple.something" in s for s in found)
    assert any("shortlog message here" in s for s in found)


def test_carve_strings_utf16le():
    text = "readable utf16 string"
    data = text.encode("utf-16-le")
    found = carve_strings(data, min_length=6)
    assert any(text in s for s in found)


def test_carve_strings_ascii_does_not_produce_utf16_garbage():
    # regression: reinterpreting plain ASCII 2-bytes-at-a-time as
    # UTF-16LE produces spurious CJK-range "strings" unless gated on
    # an actual NUL-density signal - confirmed via the GUI screenshot
    # before this was fixed.
    data = b"kernel: process 512 exited with status 0, subsystem test"
    found = carve_strings(data, min_length=6)
    assert found == ["kernel: process 512 exited with status 0, "
                     "subsystem test"]


def test_collect_end_to_end(tmp_path):
    inner_string = b"kernel: process exited with status 0 subsystem test"
    firehose = S.chunk_bytes(0x6001, inner_string)
    block = S.lz4_literal_only_block(firehose)
    chunkset_payload = b"bv41" + len(block).to_bytes(4, "little") + block
    data = (S.chunk_bytes(0x1000, b"header-bytes") +
           S.chunk_bytes(0x6100, chunkset_payload))
    p = tmp_path / "test.tracev3"
    p.write_bytes(data)

    res = collect(str(p))
    assert not res.warnings
    kinds = {r["kind"] for r in res.rows}
    assert "chunk" in kinds
    assert "string" in kinds
    strings = [r["value"] for r in res.rows if r["kind"] == "string"]
    assert any("process exited" in s for s in strings)


def test_collect_no_valid_chunks_warns(tmp_path):
    p = tmp_path / "notrace.tracev3"
    p.write_bytes(b"\x11" * 8)
    res = collect(str(p))
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    data = S.chunk_bytes(0x1000, b"abcdefgh")
    p = tmp_path / "test.tracev3"
    p.write_bytes(data)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from macos_unifiedlog.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
