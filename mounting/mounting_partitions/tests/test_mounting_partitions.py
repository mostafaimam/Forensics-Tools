from __future__ import annotations

import json

import pytest

from mounting_partitions import fsdetect
from mounting_partitions.analyze import analyze
from mounting_partitions.cli import main

import _synth as S


def test_fsdetect_units():
    assert fsdetect.detect(bytearray(3) + b"NTFS    " + bytearray(0x1F3)
                           + b"\x55\xAA") == "NTFS"
    assert fsdetect.detect(S._ext4_sb()) == "ext4"
    assert fsdetect.detect(S._swap_hdr()) == "Linux swap"
    assert fsdetect.detect(S._luks_hdr()) == "LUKS2"


def test_mbr(tmp_path):
    p = tmp_path / "disk.raw"
    p.write_bytes(S.make_mbr_disk())
    res = analyze(str(p))
    assert res.scheme == "mbr"
    assert res.image_format == "raw"
    fs = [s.filesystem for s in res.slices]
    assert fs == ["NTFS", "ext4", "FAT32", "Linux swap"]
    assert res.slices[0].bootable is True
    assert res.slices[0].start_offset == 2048 * 512


def test_gpt(tmp_path):
    p = tmp_path / "disk.raw"
    p.write_bytes(S.make_gpt_disk())
    res = analyze(str(p))
    assert res.scheme == "gpt"
    labels = [s.name for s in res.slices]
    assert "EFI System" in labels and "linux" in labels
    by_label = {s.name: s for s in res.slices}
    assert by_label["linux"].filesystem == "ext4"
    assert by_label["encrypted"].filesystem == "LUKS2"
    assert "Linux LVM" in by_label["lvm"].type_label


def test_gaps(tmp_path):
    p = tmp_path / "disk.raw"
    p.write_bytes(S.make_mbr_disk())
    res = analyze(str(p))
    # partitions start at LBA 2048 with an 8 MiB total; there is unallocated
    # space before the first partition and after the last
    kinds = {g[3] for g in res.gaps}
    assert "unallocated" in kinds
    assert any("tail" in g[3] for g in res.gaps)


def test_whole_disk_filesystem(tmp_path):
    p = tmp_path / "bare.raw"
    data = bytearray(2 * 1024 * 1024)
    data[0:512] = S._ntfs_bs()
    p.write_bytes(data)
    res = analyze(str(p))
    assert res.scheme == "none"
    assert res.slices[0].filesystem == "NTFS"
    assert res.slices[0].note == "no partition table"


def test_cli_csv_json(tmp_path):
    p = tmp_path / "disk.raw"
    p.write_bytes(S.make_gpt_disk())
    csv_p = tmp_path / "layout.csv"
    js_p = tmp_path / "layout.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 4
    assert all("start_lba" in r and "filesystem" in r for r in data)


def test_cli_text_report(tmp_path, capsys):
    p = tmp_path / "disk.raw"
    p.write_bytes(S.make_mbr_disk())
    rc = main([str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "scheme:  mbr" in out
    assert "NTFS" in out and "ext4" in out


def test_csv_injection_guard():
    from mounting_partitions.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
