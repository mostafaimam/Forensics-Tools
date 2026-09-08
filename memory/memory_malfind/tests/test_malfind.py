import csv
import json

import pytest

from memory_malfind.analyze import classify, shannon
from memory_malfind.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d
from memory_malfind.loader import MemoryImage
from memory_malfind.malfind import scan
from memory_malfind.procs import scan as proc_scan
from memory_malfind.vadscan import scan as vad_scan

import _mem


def _img(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    return MemoryImage(p)


# --------------------------------------------------------------------------
# process attribution
# --------------------------------------------------------------------------

def test_proc_scan_finds_system_with_dtb(tmp_path):
    procs = proc_scan(_img(tmp_path))
    assert len(procs) == 1
    assert procs[0].name == "System"
    assert procs[0].pid == 4
    assert procs[0].dtb == _mem.P_PPML4 * _mem.PAGE
    assert procs[0].pml4.looks_valid()


# --------------------------------------------------------------------------
# VAD scanning
# --------------------------------------------------------------------------

def test_vadscan_executable_only(tmp_path):
    vads = vad_scan(_img(tmp_path))
    ranges = {(v.start, v.protection_name) for v in vads}
    assert (_mem.VA_PE, "EXECUTE_READWRITE") in ranges
    assert (_mem.VA_SC, "EXECUTE_READ") in ranges
    assert all(v.executable and v.private for v in vads)


def test_vadscan_includes_non_exec_when_asked(tmp_path):
    vads = vad_scan(_img(tmp_path), executable_only=False)
    prots = {v.protection_name for v in vads}
    assert "READWRITE" in prots
    assert len(vads) == 3


def test_vad_geometry(tmp_path):
    v = next(x for x in vad_scan(_img(tmp_path)) if x.start == _mem.VA_PE)
    assert v.start_vpn == _mem.VA_PE >> 12
    assert v.pages == 0x20
    assert v.size == 0x20 * 0x1000 if hasattr(v, "size") else True
    assert v.end == _mem.VA_PE + 0x20 * 0x1000 - 1


# --------------------------------------------------------------------------
# content classification
# --------------------------------------------------------------------------

def test_classify_pe():
    head = bytearray(0x200)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    head[0x80:0x84] = b"PE\x00\x00"
    head[0x84:0x86] = (0x8664).to_bytes(2, "little")
    f = classify(bytes(head), 0x400000, "EXECUTE_READWRITE")
    assert f.verdict == "pe" and "x64" in f.detail


def test_classify_shellcode():
    head = b"\xfc\x48\x83\xe4\xf0\xe8" + b"\x00" * 60
    f = classify(head, 0x1a0000, "EXECUTE_READ")
    assert f.verdict == "shellcode"


def test_classify_zeroed_header():
    f = classify(b"\x00" * 0x400, 0x2000000, "EXECUTE_READWRITE")
    assert f.verdict == "unbacked-exec" and f.zeroed


def test_shannon_range():
    assert shannon(b"") == 0.0
    assert shannon(b"A" * 100) == 0.0
    assert shannon(bytes(range(256)) * 4) > 7.9


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------

def test_scan_detects_pe_and_shellcode(tmp_path):
    dets = scan(_img(tmp_path))
    by_verdict = {d.verdict: d for d in dets}
    assert "pe" in by_verdict and "shellcode" in by_verdict
    pe = by_verdict["pe"]
    assert pe.pid == 4 and pe.process == "System"
    assert pe.start == _mem.VA_PE and pe.protection == "EXECUTE_READWRITE"
    assert pe.confidence == "high"
    sc = by_verdict["shellcode"]
    assert sc.start == _mem.VA_SC
    assert "0x001a0000" in sc.hexdump


def test_scan_attributes_to_owning_process(tmp_path):
    dets = scan(_img(tmp_path))
    assert all(d.pid == 4 for d in dets)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_text_and_exit(tmp_path, capsys):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    rc = main([str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PE header present" in out
    assert "shellcode" in out


def test_cli_csv_json(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "h.csv"
    js = tmp_path / "h.json"
    main([str(p), "--csv", str(out), "--json", str(js), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert any(r["verdict"] == "pe" and r["process"] == "System" for r in rows)
    assert json.loads(js.read_text())


def test_cli_filters(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())

    out = tmp_path / "rwx.csv"
    main([str(p), "--rwx-only", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["protection"] == "EXECUTE_READWRITE" for r in rows)

    out2 = tmp_path / "pe.csv"
    main([str(p), "--verdict", "pe", "--csv", str(out2), "-q"])
    rows2 = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert len(rows2) == 1 and rows2[0]["verdict"] == "pe"

    out3 = tmp_path / "hi.csv"
    main([str(p), "--min-confidence", "high", "--csv", str(out3), "-q"])
    rows3 = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert all(r["confidence"] == "high" for r in rows3)


def test_cli_process_filter(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "s.csv"
    main([str(p), "--process", "sys", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all("system" in r["process"].lower() for r in rows)


def test_cli_missing_and_no_arg(tmp_path):
    assert main([str(tmp_path / "nope.lime")]) == 2
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    import _mem as m
    mem = bytearray(m.N_PAGES * m.PAGE)
    m._kernel_tables(mem)
    m._process_tables(mem)
    off = m.P_SYSTEM * m.PAGE
    mem[off + 0x10:off + 0x14] = b"Proc"
    mem[off + 0x20:off + 0x28] = (m.P_PPML4 * m.PAGE).to_bytes(8, "little")
    mem[off + 0x30:off + 0x34] = (4).to_bytes(4, "little")
    mem[off + 0x50:off + 0x5a] = b"=calc.exe\x00"
    m._vad_short(mem, m.P_VAD_RWX, m.VA_PE >> 12, (m.VA_PE >> 12) + 1, 6)
    m._pe_header(mem, m.P_PE)
    p = tmp_path / "m.lime"
    p.write_bytes(m._lime(bytes(mem)))
    out = tmp_path / "o.csv"
    main([str(p), "--csv", str(out), "-q"])
    assert "'=calc.exe" in out.read_text(encoding="utf-8-sig")
