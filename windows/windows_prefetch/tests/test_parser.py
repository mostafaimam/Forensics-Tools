import os
from datetime import datetime, timezone

import pytest

from _synth import make_scca_v30, wrap_mam
from windows_prefetch.parser import parse_bytes, parse_file

RUNS = [
    datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
    datetime(2024, 2, 28, 9, 30, 0, tzinfo=timezone.utc),
]
REFS = [
    r"\VOLUME{01d8a1a0-00000000}\WINDOWS\SYSTEM32\NTDLL.DLL",
    r"\VOLUME{01d8a1a0-00000000}\WINDOWS\SYSTEM32\KERNEL32.DLL",
    r"\VOLUME{01d8a1a0-00000000}\WINDOWS\NOTEPAD.EXE",
]


def test_parse_uncompressed_v30():
    scca = make_scca_v30("NOTEPAD.EXE", RUNS, 7, REFS)
    pf = parse_bytes(scca, "NOTEPAD.EXE-D8414F97.pf")
    assert not pf.parse_error
    assert pf.format_version == 30
    assert pf.executable == "NOTEPAD.EXE"
    assert pf.run_count == 7
    assert pf.run_times[:2] == RUNS
    assert pf.referenced_files == REFS
    assert pf.referenced_file_count == 3
    assert len(pf.volumes) == 1
    assert pf.volumes[0].serial_hex == "1A2B3C4D"
    assert not pf.is_compressed


@pytest.mark.skipif(os.name != "nt", reason="MAM build needs ntdll")
def test_parse_mam_compressed_roundtrip():
    scca = make_scca_v30("CHROME.EXE", RUNS, 42, REFS)
    mam = wrap_mam(scca)
    assert mam[:4] == b"MAM\x04"

    pf = parse_bytes(mam, "CHROME.EXE-ABCDEF01.pf")
    assert not pf.parse_error
    assert pf.is_compressed
    assert pf.executable == "CHROME.EXE"
    assert pf.run_count == 42
    assert pf.referenced_files == REFS

    # force the pure-Python decompressor
    os.environ["WINDOWS_PREFETCH_NO_NATIVE"] = "1"
    try:
        pf2 = parse_bytes(mam, "CHROME.EXE-ABCDEF01.pf")
    finally:
        del os.environ["WINDOWS_PREFETCH_NO_NATIVE"]
    assert pf2.decompressor == "python"
    assert pf2.to_json() == pf.to_json() or pf2.referenced_files == REFS


def test_variant_a_layout():
    scca = make_scca_v30("OLD.EXE", RUNS, 3, REFS, variant="a")
    pf = parse_bytes(scca)
    assert pf.run_count == 3
    assert pf.run_times[:2] == RUNS


def test_version_31():
    scca = make_scca_v30("WIN11.EXE", RUNS, 5, REFS, version=31)
    pf = parse_bytes(scca)
    assert pf.format_version == 31
    assert pf.run_count == 5
    assert pf.referenced_files == REFS


def test_not_a_prefetch_file():
    pf = parse_bytes(b"PK\x03\x04 not prefetch at all")
    assert pf.parse_error
    assert "not a Prefetch file" in pf.parse_error


def test_truncated_scca():
    pf = parse_bytes(b"SCCA" + b"\x00" * 10)
    assert pf.parse_error


def test_unsupported_version():
    scca = bytearray(make_scca_v30("X.EXE", RUNS, 1, REFS))
    scca[0:4] = (99).to_bytes(4, "little")
    pf = parse_bytes(bytes(scca))
    assert "unsupported Prefetch version 99" in pf.parse_error


def test_zero_filetime_skipped():
    scca = make_scca_v30("Y.EXE", [RUNS[0]], 1, REFS)  # only 1 real run time
    pf = parse_bytes(scca)
    assert pf.run_times == [RUNS[0]]


def test_parse_file_missing(tmp_path):
    pf = parse_file(tmp_path / "nope.pf")
    assert pf.parse_error and "cannot read" in pf.parse_error
