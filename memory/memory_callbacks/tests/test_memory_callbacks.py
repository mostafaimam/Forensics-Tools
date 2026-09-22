from __future__ import annotations

import json
import struct

import pytest

from memory_callbacks.callbackscan import _canonical, _classify, \
    _cluster_bounds, scan
from memory_callbacks.loader import MemoryImage
from memory_callbacks.collect import scan_image
from memory_callbacks.cli import main


def _write_image(tmp_path, data: bytes):
    p = tmp_path / "mem.raw"
    p.write_bytes(data)
    return p




def test_canonical_check():
    assert _canonical(0xFFFFF80001000000)
    assert not _canonical(0)


def test_classify_all_null_ok_but_empty():
    ok, masked = _classify([0] * 8)
    assert ok
    assert masked == []


def test_classify_mixed_registered():
    entries = [0, 0xFFFFF80001001000, 0, 0, 0xFFFFF80001002008, 0, 0, 0]
    ok, masked = _classify(entries)
    assert ok
    assert len(masked) == 2


def test_classify_rejects_garbage_nonnull():
    entries = [0, 0x1234, 0, 0, 0, 0, 0, 0]  # not canonical
    ok, masked = _classify(entries)
    assert not ok


def test_classify_masks_low_flag_bits():
    # low nibble carries flag bits in some callback-pointer conventions
    entries = [0xFFFFF80001001003] + [0] * 7
    ok, masked = _classify(entries)
    assert ok
    assert masked == [0xFFFFF80001001000]


def test_cluster_bounds_tight():
    ptrs = [0xFFFFF80001000000 + i * 0x40 for i in range(4)]
    bounds = _cluster_bounds(ptrs)
    assert bounds is not None


def _make_array(size: int, registered: dict[int, int]) -> bytes:
    entries = [0] * size
    for idx, val in registered.items():
        entries[idx] = val
    return b"".join(struct.pack("<Q", v) for v in entries)


def _noise(n: int) -> bytes:
    # real kernel memory is packed with other data, not a zero desert -
    # a long run of pure zeros ahead of a sparse array is inherently
    # alignment-ambiguous (any shifted window overlapping the zero run
    # can tie the true array on non-null count, since zeros carry no
    # distinguishing signal either way); non-zero noise reflects the
    # tool's real operating environment and removes that ambiguity.
    return bytes((i * 91 + 13) % 256 or 1 for i in range(n))


def test_scan_finds_registered_callbacks_no_outliers(tmp_path):
    arr = _make_array(8, {1: 0xFFFFF80001001000, 4: 0xFFFFF80001002000})
    data = _noise(4096) + arr
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        candidates = scan(img, verify_mapped=False, sizes=(8,))
    assert len(candidates) == 1
    c = candidates[0]
    assert c.non_null_indices == [1, 4]
    assert c.outlier_indices == []


def test_scan_flags_outlier_callback(tmp_path):
    arr = _make_array(8, {
        0: 0xFFFFF80001001000, 2: 0xFFFFF80001001100,
        3: 0xFFFFF80001001200, 5: 0xFFFFFAAA99990000,  # far outlier
    })
    data = _noise(4096) + arr
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        candidates = scan(img, verify_mapped=False, sizes=(8,))
    assert len(candidates) == 1
    assert 5 in candidates[0].outlier_indices


def test_scan_all_null_array_not_reported(tmp_path):
    arr = _make_array(8, {})
    data = _noise(4096) + arr + _noise(4096)
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        candidates = scan(img, verify_mapped=False, sizes=(8,))
    assert candidates == []


def test_scan_no_candidates_on_random_noise(tmp_path):
    data = bytes((i * 53 + 7) % 256 for i in range(8192))
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        candidates = scan(img, verify_mapped=False, sizes=(8, 64))
    assert candidates == []


def test_collect_end_to_end(tmp_path):
    arr = _make_array(8, {1: 0xFFFFF80001001000, 4: 0xFFFFF80001002000})
    data = _noise(4096) + arr
    p = _write_image(tmp_path, data)
    res = scan_image(str(p))
    assert res.rows
    assert res.rows[0]["registered_count"] == 2


def test_collect_warns_when_empty(tmp_path):
    data = bytes((i * 53 + 7) % 256 for i in range(8192))
    p = _write_image(tmp_path, data)
    res = scan_image(str(p))
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    arr = _make_array(8, {2: 0xFFFFF80001001000})
    data = _noise(4096) + arr
    p = _write_image(tmp_path, data)
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
    from memory_callbacks.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
