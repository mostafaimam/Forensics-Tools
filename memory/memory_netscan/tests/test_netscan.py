import csv
import json

from memory_netscan.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d
from memory_netscan.loader import MemoryImage
from memory_netscan.netscan import scan
from memory_netscan.pagemap import Pml4, find_kernel_dtb

import _mem


def _img(tmp_path, builder=_mem.build_image):
    p = tmp_path / "mem.lime"
    p.write_bytes(builder())
    return MemoryImage(p)


# --------------------------------------------------------------------------
# page-table translation
# --------------------------------------------------------------------------

def test_find_dtb_and_translate(tmp_path):
    img = _img(tmp_path)
    dtb = find_kernel_dtb(img)
    assert dtb == _mem.P_PML4 * _mem.PAGE
    pml4 = Pml4(img, dtb)
    assert pml4.looks_valid()
    assert pml4.translate(_mem.KBASE) == _mem.P_SYSTEM * _mem.PAGE
    assert pml4.translate(_mem.va_of(_mem.P_INADDR)) == _mem.P_INADDR * _mem.PAGE
    # an unmapped kernel address
    assert pml4.translate(_mem.KBASE + 0x50 * _mem.PAGE) is None


def test_translation_reads_across_page(tmp_path):
    img = _img(tmp_path)
    pml4 = Pml4(img, find_kernel_dtb(img))
    data = pml4.read(_mem.va_of(_mem.P_SYSTEM) + 0x40, 7)
    assert data == b"System\x00"


def test_no_dtb_returns_none(tmp_path):
    img = _img(tmp_path, _mem.build_image_no_dtb)
    assert find_kernel_dtb(img, limit=1 << 20) is None


# --------------------------------------------------------------------------
# endpoint scanning
# --------------------------------------------------------------------------

def test_scan_finds_all_three_kinds(tmp_path):
    eps = scan(_img(tmp_path))
    kinds = {(e.proto, e.role) for e in eps}
    assert ("TCP", "endpoint") in kinds
    assert ("TCP", "listener") in kinds
    assert ("UDP", "endpoint") in kinds


def test_tcp_endpoint_fields(tmp_path):
    eps = scan(_img(tmp_path))
    tcpe = next(e for e in eps if e.pool_tag == "TcpE")
    assert tcpe.state == "ESTABLISHED"
    assert tcpe.local_port == 49213
    assert tcpe.remote_port == 443
    assert tcpe.local_addr == "10.0.2.15"
    assert tcpe.pid == 4
    assert tcpe.process == "System"
    assert tcpe.create_time == "2026-03-01T09:15:00Z"
    assert tcpe.confidence == "high"


def test_listener_and_udp_ports(tmp_path):
    eps = scan(_img(tmp_path))
    lis = next(e for e in eps if e.pool_tag == "TcpL")
    assert lis.state == "LISTENING" and lis.local_port == 445
    udp = next(e for e in eps if e.pool_tag == "UdpA")
    assert udp.local_port == 138 and udp.proto == "UDP"


def test_degrades_without_translation(tmp_path):
    img = _img(tmp_path)
    eps = scan(img, use_translation=False)
    tcpe = next(e for e in eps if e.pool_tag == "TcpE")
    # ports / state / time still recovered inline, but no process / address
    assert tcpe.local_port == 49213 and tcpe.state == "ESTABLISHED"
    assert tcpe.process == "" and tcpe.local_addr in ("0.0.0.0", "")
    assert tcpe.confidence in ("low", "medium")


def test_no_dtb_image_still_lists_endpoint(tmp_path):
    eps = scan(_img(tmp_path, _mem.build_image_no_dtb))
    assert any(e.pool_tag == "TcpE" and e.local_port == 49213 for e in eps)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_csv(tmp_path):
    p = tmp_path / "mem.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "n.csv"
    rc = main([str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 3
    assert any(r["process"] == "System" and r["local_port"] == "49213"
               for r in rows)


def test_cli_filters(tmp_path):
    p = tmp_path / "mem.lime"
    p.write_bytes(_mem.build_image())

    out = tmp_path / "tcp.json"
    main([str(p), "--proto", "tcp", "--json", str(out), "-q"])
    assert all(r["proto"] == "TCP" for r in _recs(out))

    out2 = tmp_path / "lis.csv"
    main([str(p), "--listeners", "--csv", str(out2), "-q"])
    lrows = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert len(lrows) == 1 and lrows[0]["role"] == "listener"

    out3 = tmp_path / "est.csv"
    main([str(p), "--established", "--csv", str(out3), "-q"])
    erows = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert len(erows) == 1 and erows[0]["state"] == "ESTABLISHED"

    out4 = tmp_path / "p443.csv"
    main([str(p), "--port", "443", "--csv", str(out4), "-q"])
    assert len(list(csv.DictReader(out4.open(encoding="utf-8-sig")))) == 1


def test_cli_process_filter(tmp_path):
    p = tmp_path / "mem.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "sys.csv"
    main([str(p), "--process", "sys", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all("system" in r["process"].lower() for r in rows)


def test_cli_missing_and_help(tmp_path):
    import pytest
    assert main([str(tmp_path / "nope.lime")]) == 2
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    # a process name that starts with '=' must be quoted
    import _mem as m
    mem = bytearray(m.N_PAGES * m.PAGE)
    m._page_tables(mem)
    off = m.P_SYSTEM * m.PAGE
    mem[off + 0x20:off + 0x28] = (4).to_bytes(8, "little")
    mem[off + 0x40:off + 0x48] = b"=evil.exe"
    m._proc_tag_with_dtb(mem)
    m._inetaf(mem)
    m._inaddr(mem)
    m._endpoint(mem, m.P_TCPE, b"TcpE", state=4, lport=1234, rport=80,
                when=__import__("datetime").datetime(2026, 1, 1))
    p = tmp_path / "m.lime"
    p.write_bytes(m._lime(bytes(mem)))
    out = tmp_path / "o.csv"
    main([str(p), "--csv", str(out), "-q"])
    assert "'=evil.exe" in out.read_text(encoding="utf-8-sig")
