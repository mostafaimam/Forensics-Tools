from __future__ import annotations

import json
import struct

import pytest

import _fat_synth as FAT
import _exfat_synth as XFAT
import _ntfs_synth as NTFS

from recovery_fs.detect import detect
from recovery_fs.open import open_fs, FsError
from recovery_fs.cli import main


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_detect():
    assert detect(FAT.build_fat16()[:0x600]) == "fat"
    assert detect(XFAT.build_exfat()[:0x600]) == "exfat"
    assert detect(NTFS.build_ntfs_image()[0][:0x600]) == "ntfs"
    ext = bytearray(0x600)
    ext[0x438:0x43A] = b"\x53\xef"
    assert detect(bytes(ext)) == "ext"


def test_fat_walk(tmp_path):
    be, off, fs = open_fs(str(_write(tmp_path, "f.img", FAT.build_fat16())))
    assert fs in ("fat12", "fat16")
    ents = {e.path: e for e in be.entries()}
    assert ents["HELLO.TXT"].size == 26
    assert ents["HELLO.TXT"].modified.startswith("2026-03-16")
    assert not ents["_ECRET.TXT"].allocated
    assert ents["DOCS"].is_dir
    assert "DOCS/NOTE.TXT" in ents
    assert be.read(ents["HELLO.TXT"]).startswith(b"hello from a FAT16")
    assert be.read(ents["DOCS/NOTE.TXT"]) == b"nested note file\n"


def test_exfat_walk(tmp_path):
    be, off, fs = open_fs(str(_write(tmp_path, "x.img", XFAT.build_exfat())))
    assert fs == "exfat"
    ents = {e.path: e for e in be.entries()}
    assert ents["hello.txt"].size == 44
    assert ents["sub"].is_dir
    assert be.read(ents["sub/note.txt"]) == b"exfat nested note\n"


def test_ntfs_walk(tmp_path):
    img, meta = NTFS.build_ntfs_image()
    be, off, fs = open_fs(str(_write(tmp_path, "n.img", img)))
    assert fs == "ntfs"
    ents = {e.name: e for e in be.entries()}
    assert "hello.txt" in ents and "secret.txt" in ents
    assert not ents["secret.txt"].allocated
    assert be.read(ents["hello.txt"]) == meta["hello.txt"]


def test_partition_autodetect(tmp_path):
    fatimg = FAT.build_fat16()
    disk = bytearray(2048 * 512 + len(fatimg))
    part_lba = 2048
    disk[part_lba * 512: part_lba * 512 + len(fatimg)] = fatimg
    # MBR: one primary partition, type 0x06, starting at LBA 2048
    disk[446 + 4] = 0x06
    struct.pack_into("<I", disk, 446 + 8, part_lba)
    disk[510:512] = b"\x55\xaa"
    be, off, fs = open_fs(str(_write(tmp_path, "disk.raw", bytes(disk))))
    assert off == part_lba * 512
    assert fs in ("fat12", "fat16")


def test_unsupported_fs(tmp_path):
    ext = bytearray(0x800)
    ext[0x438:0x43A] = b"\x53\xef"
    with pytest.raises(FsError):
        open_fs(str(_write(tmp_path, "e.img", bytes(ext))), offset=0)


def test_cli_list_extract_bodyfile(tmp_path):
    img = _write(tmp_path, "f.img", FAT.build_fat16())
    js = tmp_path / "l.json"
    rc = main(["list", str(img), "--json", str(js), "-q"])
    assert rc == 0
    rows = json.loads(js.read_text())
    assert any(r["path"] == "HELLO.TXT" for r in rows)
    assert any(r["allocated"] == "DELETED" for r in rows)

    rc = main(["list", str(img), "--deleted-only", "--json", str(js), "-q"])
    assert all(r["allocated"] == "DELETED" for r in json.loads(js.read_text()))

    out = tmp_path / "out"
    rc = main(["extract", str(img), "--glob", "DOCS/*", "-o", str(out), "-q"])
    assert rc == 0
    assert (out / "DOCS/NOTE.TXT").read_bytes() == b"nested note file\n"

    body = tmp_path / "fs.body"
    main(["bodyfile", str(img), "-o", str(body), "-q"])
    lines = body.read_text().strip().splitlines()
    assert lines and lines[0].count("|") == 10

    cat = tmp_path / "h.txt"
    main(["cat", str(img), "--path", "HELLO.TXT", "-o", str(cat), "-q"])
    assert cat.read_bytes().startswith(b"hello")


def test_csv_injection_guard():
    from recovery_fs.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
