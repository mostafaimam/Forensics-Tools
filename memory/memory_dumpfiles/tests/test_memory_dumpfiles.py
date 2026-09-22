from __future__ import annotations

import json

import pytest

import _mem

from memory_dumpfiles.loader import MemoryImage
from memory_dumpfiles.pagemap import Pml4, find_kernel_dtb
from memory_dumpfiles.vacbscan import read_cached_view, scan
from memory_dumpfiles.collect import scan_image
from memory_dumpfiles.cli import main


def _write_image(tmp_path, data: bytes):
    p = tmp_path / "mem.raw"
    p.write_bytes(data)
    return p


def test_file_object_without_cache_chain_found_by_name(tmp_path):
    b = _mem.Builder()
    b.file_object(r"\Device\HarddiskVolume1\Windows\System32\plain.txt")
    p = _write_image(tmp_path, b.bytes())
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert len(hits) == 1
    assert hits[0].name.endswith("plain.txt")
    assert hits[0].vacbs == []


def test_file_object_with_cache_chain_self_verifies(tmp_path):
    b = _mem.Builder()
    content = b"cached file content for the forensic test case" * 20
    b.file_object_with_cache(
        r"\Device\HarddiskVolume1\Windows\System32\cached.dat", content)
    p = _write_image(tmp_path, b.bytes())
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert len(hits) == 1
    assert hits[0].vacbs, "expected the VACB chain to self-verify"
    assert len(hits[0].vacbs) == 1


def test_read_cached_view_recovers_content(tmp_path):
    b = _mem.Builder()
    content = b"exact recoverable bytes here" * 30
    b.file_object_with_cache(
        r"\Device\HarddiskVolume1\Users\a\Desktop\evidence.docx", content)
    p = _write_image(tmp_path, b.bytes())
    with MemoryImage(str(p)) as img:
        dtb = find_kernel_dtb(img)
        pml4 = Pml4(img, dtb)
        hits = scan(img)
        view = read_cached_view(pml4, hits[0].vacbs[0])
    assert view.startswith(content[:64])


def test_wrong_back_pointer_rejected(tmp_path):
    # a VACB whose back-pointer does NOT match its SharedCacheMap must
    # never be accepted - this is the self-verification this whole
    # tool's confidence rests on.
    b = _mem.Builder()
    content_va = b.write_bytes_page(b"should never be reachable" * 10)
    scm_pg = b.alloc()
    scm_va = b.kernel_va(scm_pg)
    wrong_back_pointer = scm_va ^ 0x1000   # deliberately wrong
    vacb_va = b.vacb(content_va, wrong_back_pointer, 0)
    import struct
    struct.pack_into("<Q", b.mem, scm_pg * 0x1000 + 0x40, vacb_va)
    sop_va = b.section_object_pointers(scm_va)
    b.file_object(r"\Device\HarddiskVolume1\bad.dat",
                  section_object_pointers_va=sop_va)
    p = _write_image(tmp_path, b.bytes())
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert hits[0].vacbs == []


def test_multiple_file_objects_independent(tmp_path):
    b = _mem.Builder()
    b.file_object(r"\Device\HarddiskVolume1\a.txt")
    b.file_object_with_cache(r"\Device\HarddiskVolume1\b.txt",
                             b"content of b" * 20)
    p = _write_image(tmp_path, b.bytes())
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert len(hits) == 2
    by_name = {h.name.rsplit("\\", 1)[-1]: h for h in hits}
    assert by_name["a.txt"].vacbs == []
    assert by_name["b.txt"].vacbs


def test_collect_reports_gap_when_no_dtb(tmp_path):
    p = _write_image(tmp_path, b"\x00" * 0x10000)
    res = scan_image(str(p))
    assert not res.rows
    assert res.warnings


def test_collect_end_to_end_rows(tmp_path):
    b = _mem.Builder()
    b.file_object_with_cache(r"\Device\HarddiskVolume1\c.dat",
                             b"c-content" * 40)
    p = _write_image(tmp_path, b.bytes())
    res = scan_image(str(p))
    assert res.rows
    assert any(r["view_size"] for r in res.rows)


def test_collect_dump_dir_writes_file(tmp_path):
    b = _mem.Builder()
    b.file_object_with_cache(r"\Device\HarddiskVolume1\d.dat",
                             b"d-content" * 40)
    p = _write_image(tmp_path, b.bytes())
    out_dir = tmp_path / "out"
    res = scan_image(str(p), dump_dir=str(out_dir))
    assert any(out_dir.glob("*.bin"))


def test_cli_csv_json(tmp_path):
    b = _mem.Builder()
    b.file_object(r"\Device\HarddiskVolume1\e.txt")
    p = _write_image(tmp_path, b.bytes())
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
    from memory_dumpfiles.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
