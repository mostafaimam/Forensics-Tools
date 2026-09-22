from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from mounting_vsc.vss import _VSS_MAGIC, filetime_to_utc, scan
from mounting_vsc.collect import collect
from mounting_vsc.cli import main


def _filetime_for(dt: datetime) -> int:
    unix_ns = int((dt - datetime(1970, 1, 1, tzinfo=timezone.utc))
                 .total_seconds() * 10_000_000)
    return unix_ns + 116444736000000000


def test_filetime_roundtrip():
    dt = datetime(2026, 6, 15, 12, 30, tzinfo=timezone.utc)
    value = _filetime_for(dt)
    recovered = filetime_to_utc(value)
    assert recovered is not None
    assert abs((recovered - dt).total_seconds()) < 1


def test_filetime_implausible_rejected():
    assert filetime_to_utc(1) is None  # far too early
    assert filetime_to_utc(2**63 - 1) is None  # far too late / overflow-ish


def test_scan_finds_vss_magic():
    data = b"\x00" * 100 + _VSS_MAGIC + b"\x00" * 400
    hits = scan(data)
    assert len(hits) == 1
    assert hits[0].offset == 100


def test_scan_finds_multiple_hits():
    data = _VSS_MAGIC + b"\x00" * 600 + _VSS_MAGIC + b"\x00" * 600
    hits = scan(data)
    assert len(hits) == 2
    assert hits[1].offset == 16 + 600


def test_scan_finds_nearby_filetime():
    dt = datetime(2026, 3, 1, tzinfo=timezone.utc)
    ft_bytes = _filetime_for(dt).to_bytes(8, "little")
    data = _VSS_MAGIC + b"\x00" * 20 + ft_bytes + b"\x00" * 400
    hits = scan(data)
    assert len(hits) == 1
    offsets = {f["offset"] for f in hits[0].candidate_filetimes}
    assert (16 + 20) in offsets


def test_scan_finds_nearby_guid():
    some_guid = uuid.uuid4()
    data = _VSS_MAGIC + b"\x00" * 40 + some_guid.bytes_le + b"\x00" * 400
    hits = scan(data)
    assert len(hits) == 1
    found = {g["guid"] for g in hits[0].candidate_guids}
    assert str(some_guid) in found


def test_scan_no_hits_on_random_data():
    hits = scan(b"\x11" * 4096)
    assert hits == []


def test_collect_flattens_rows(tmp_path):
    dt = datetime(2026, 5, 5, tzinfo=timezone.utc)
    ft_bytes = _filetime_for(dt).to_bytes(8, "little")
    data = _VSS_MAGIC + b"\x00" * 20 + ft_bytes + b"\x00" * 400
    p = tmp_path / "volume.img"
    p.write_bytes(data)
    res = collect(str(p))
    kinds = {r["kind"] for r in res.rows}
    assert "vss_identifier" in kinds
    assert "filetime" in kinds
    assert not res.warnings


def test_collect_no_hits_warns(tmp_path):
    p = tmp_path / "empty.img"
    p.write_bytes(b"\x00" * 4096)
    res = collect(str(p))
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    data = _VSS_MAGIC + b"\x00" * 400
    p = tmp_path / "volume.img"
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
    from mounting_vsc.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
