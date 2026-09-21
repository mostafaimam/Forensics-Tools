from __future__ import annotations

import json

import pytest

import _synth as S

from memory_timers.timerscan import scan_block, scan_stream
from memory_timers.collect import scan_image
from memory_timers.cli import main


def test_scan_block_finds_valid_ktimer():
    blob = S.build_ktimer()
    padded = b"\x00" * 200 + blob + b"\x00" * 200
    hits = scan_block(padded)
    assert len(hits) == 1
    assert hits[0].phys_offset == 200
    assert hits[0].timer_type == "TimerNotificationObject"


def test_synchronization_timer_type_accepted():
    blob = S.build_ktimer(timer_type=9)
    hits = scan_block(blob)
    assert hits and hits[0].timer_type == "TimerSynchronizationObject"


def test_wrong_type_byte_rejected():
    blob = S.build_ktimer(timer_type=3)   # ProcessObject, not a timer
    assert scan_block(blob) == []


def test_bad_size_field_rejected():
    blob = S.build_ktimer(size=200)
    assert scan_block(blob) == []


def test_non_canonical_pointer_rejected():
    blob = S.build_ktimer(flink=0x1234, blink=0x5678)
    assert scan_block(blob) == []


def test_non_canonical_dpc_rejected():
    blob = S.build_ktimer(dpc=0x41414141)
    assert scan_block(blob) == []


def test_null_dpc_accepted():
    blob = S.build_ktimer(dpc=S.NULL_PTR)
    hits = scan_block(blob)
    assert hits


def test_period_win8_layout_picked():
    blob = S.build_ktimer(period=2500, with_processor_field=True)
    hits = scan_block(blob)
    assert hits[0].period_ms == 2500


def test_period_pre_win8_layout_picked():
    blob = S.build_ktimer(period=1500, with_processor_field=False)
    hits = scan_block(blob)
    assert hits[0].period_ms == 1500


def test_relative_due_time_decoded(tmp_path):
    from memory_timers.collect import _decode_due_time
    blob = S.build_ktimer(due_time=0xFFFFFFFFFFFFFF00)  # small negative
    hits = scan_block(blob)
    decoded = _decode_due_time(hits[0].due_time)
    assert "relative" in decoded


def test_scan_stream_across_chunk_boundary():
    blob = S.build_ktimer()
    filler = b"\x00" * 300
    data = filler + blob + filler
    chunk_size = 40
    chunks = [(i, data[i:i + chunk_size])
             for i in range(0, len(data), chunk_size)]
    hits = scan_stream(iter(chunks))
    assert len(hits) == 1
    assert hits[0].phys_offset == 300


def test_scan_image_end_to_end(tmp_path):
    blob = S.build_ktimer(period=750)
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00" * 500 + blob + b"\x00" * 500)
    res = scan_image(str(img))
    assert not res.warnings
    assert len(res.rows) == 1
    assert res.rows[0]["period_ms"] == 750


def test_scan_image_no_hits_warns(tmp_path):
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00" * 1000)
    res = scan_image(str(img))
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    blob = S.build_ktimer()
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00" * 200 + blob + b"\x00" * 200)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(img), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_periodic_only(tmp_path):
    one_shot = S.build_ktimer(period=0)
    periodic = S.build_ktimer(period=5000)
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00" * 200 + one_shot + b"\x00" * 200 + periodic +
                    b"\x00" * 200)
    js_p = tmp_path / "out.json"
    rc = main([str(img), "--periodic-only", "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["period_ms"] for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from memory_timers.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
