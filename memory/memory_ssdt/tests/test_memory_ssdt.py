from __future__ import annotations

import json
import struct

import pytest

from memory_ssdt.ssdtscan import Candidate, _canonical, _cluster_bounds, \
    _find_runs
from memory_ssdt.loader import MemoryImage
from memory_ssdt.collect import scan_image
from memory_ssdt.cli import main


def _clustered_ptrs(n: int, base: int = 0xFFFFF80001000000,
                    spread: int = 0x800) -> list[int]:
    return [base + (i * spread // max(n, 1)) for i in range(n)]


def test_canonical_check():
    assert _canonical(0xFFFFF80001000000)
    assert not _canonical(0)
    assert not _canonical(0x0000000140000000)  # userland-ish, not kernel


def test_cluster_bounds_tight_run():
    ptrs = _clustered_ptrs(40)
    bounds = _cluster_bounds(ptrs)
    assert bounds is not None
    lo, hi = bounds
    assert hi - lo <= 0x800


def test_cluster_bounds_scattered_rejected():
    import random
    rng = random.Random(1)
    ptrs = [0xFFFF800000000000 | (rng.getrandbits(40) << 8)
           for _ in range(40)]
    bounds = _cluster_bounds(ptrs)
    assert bounds is None


def test_find_runs_detects_clustered_array():
    ptrs = _clustered_ptrs(40)
    block = b"\x00" * 64 + b"".join(struct.pack("<Q", p) for p in ptrs)
    runs = _find_runs(block)
    assert len(runs) == 1
    off, found = runs[0]
    assert off == 64
    assert found == ptrs


def test_find_runs_ignores_short_runs():
    ptrs = _clustered_ptrs(10)   # below _MIN_ENTRIES
    block = b"".join(struct.pack("<Q", p) for p in ptrs)
    assert _find_runs(block) == []


def _write_image(tmp_path, data: bytes):
    p = tmp_path / "mem.raw"
    p.write_bytes(data)
    return p


def test_scan_finds_clean_cluster_no_outliers(tmp_path):
    ptrs = _clustered_ptrs(64)
    data = b"\x00" * 4096 + b"".join(struct.pack("<Q", p) for p in ptrs)
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        from memory_ssdt.ssdtscan import scan
        candidates = scan(img, verify_mapped=False)
    assert len(candidates) == 1
    assert candidates[0].outliers == []


def test_scan_flags_outlier_pointer(tmp_path):
    ptrs = _clustered_ptrs(64)
    ptrs[10] = 0xFFFFF9AA00000000   # far outside the cluster
    data = b"\x00" * 4096 + b"".join(struct.pack("<Q", p) for p in ptrs)
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        from memory_ssdt.ssdtscan import scan
        candidates = scan(img, verify_mapped=False)
    assert len(candidates) == 1
    outlier_indices = {i for i, _ in candidates[0].outliers}
    assert 10 in outlier_indices


def test_scan_no_candidates_on_random_noise(tmp_path):
    data = bytes((i * 37 + 5) % 256 for i in range(8192))
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        from memory_ssdt.ssdtscan import scan
        candidates = scan(img, verify_mapped=False)
    assert candidates == []


def test_collect_reports_warning_on_empty(tmp_path):
    data = bytes((i * 37 + 5) % 256 for i in range(8192))
    p = _write_image(tmp_path, data)
    res = scan_image(str(p))
    assert not res.rows
    assert res.warnings


def test_collect_end_to_end(tmp_path):
    ptrs = _clustered_ptrs(64)
    data = b"\x00" * 4096 + b"".join(struct.pack("<Q", p) for p in ptrs)
    p = _write_image(tmp_path, data)
    res = scan_image(str(p), min_entries=32)
    assert res.rows
    assert res.rows[0]["entry_count"] == 64


def test_cli_csv_json(tmp_path):
    ptrs = _clustered_ptrs(64)
    data = b"\x00" * 4096 + b"".join(struct.pack("<Q", p) for p in ptrs)
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
    from memory_ssdt.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
