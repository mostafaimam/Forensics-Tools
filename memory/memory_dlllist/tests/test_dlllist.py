import csv
import json

import pytest

from memory_dlllist.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d
from memory_dlllist.dlllist import scan
from memory_dlllist.imagevad import scan as vad_scan
from memory_dlllist.loader import MemoryImage
from memory_dlllist.procs import scan as proc_scan

import _mem


def _img(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    return MemoryImage(p)


def test_proc_scan(tmp_path):
    procs = proc_scan(_img(tmp_path))
    assert len(procs) == 1
    assert procs[0].name == "services.exe" and procs[0].pid == 680


def test_imagevad_resolves_paths(tmp_path):
    vads = vad_scan(_img(tmp_path))
    by_start = {v.start: v for v in vads}
    assert by_start[_mem.VA_NTDLL].file_path == _mem.NTDLL_PATH
    assert by_start[_mem.VA_EVIL].file_path == _mem.EVIL_PATH
    assert by_start[_mem.VA_NOFILE].file_path == ""
    assert by_start[_mem.VA_NOFILE].backed is False


def test_imagevad_high_vpn(tmp_path):
    """A DLL loaded above the 44-bit line still parses."""
    v = next(x for x in vad_scan(_img(tmp_path)) if x.start == _mem.VA_NTDLL)
    assert v.start == _mem.VA_NTDLL
    assert v.end == _mem.VA_NTDLL + 0x40 * 0x1000 - 1


def test_dlllist_attributes_and_flags(tmp_path):
    mods = scan(_img(tmp_path))
    assert {m.name for m in mods} == {"ntdll.dll", "evil.dll", ""}
    assert all(m.pid == 680 and m.process == "services.exe" for m in mods)

    ntdll = next(m for m in mods if m.name == "ntdll.dll")
    assert ntdll.notable == []                    # clean system path

    evil = next(m for m in mods if m.name == "evil.dll")
    assert "user-writable-path" in evil.notable

    nofile = next(m for m in mods if m.name == "")
    assert "unbacked-image" in nofile.notable


def test_dlllist_system_dll_wrong_path(tmp_path):
    b = _mem.Builder()
    b.image_vad(_mem.VA_NTDLL, 8,
                "\\Device\\HarddiskVolume2\\Users\\bob\\Downloads\\ntdll.dll")
    p = tmp_path / "m.lime"
    p.write_bytes(b.lime())
    mods = scan(MemoryImage(p))
    m = next(x for x in mods if x.name == "ntdll.dll")
    assert "system-dll-wrong-path" in m.notable
    assert "user-writable-path" in m.notable


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_text(tmp_path, capsys):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    rc = main([str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "services.exe" in out and "ntdll.dll" in out
    assert "evil.dll" in out


def test_cli_csv_json(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "m.csv"
    js = tmp_path / "m.json"
    main([str(p), "--csv", str(out), "--json", str(js), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert any(r["name"] == "ntdll.dll" for r in rows)
    assert json.loads(js.read_text())


def test_cli_filters(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())

    out = tmp_path / "n.csv"
    main([str(p), "--notable-only", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["notable"] for r in rows)
    assert not any(r["name"] == "ntdll.dll" for r in rows)

    out2 = tmp_path / "u.csv"
    main([str(p), "--unbacked-only", "--csv", str(out2), "-q"])
    urows = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert len(urows) == 1 and "unbacked-image" in urows[0]["notable"]

    out3 = tmp_path / "name.csv"
    main([str(p), "--name", "evil", "--csv", str(out3), "-q"])
    nrows = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert len(nrows) == 1 and nrows[0]["name"] == "evil.dll"


def test_cli_process_filter(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.build_image())
    out = tmp_path / "s.csv"
    main([str(p), "--process", "services", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all("services" in r["process"] for r in rows)


def test_cli_missing_and_no_arg(tmp_path):
    assert main([str(tmp_path / "nope.lime")]) == 2
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    b = _mem.Builder()
    b.image_vad(_mem.VA_EVIL, 4,
                "\\Device\\X\\Users\\a\\Temp\\=cmd|calc.dll")
    p = tmp_path / "m.lime"
    p.write_bytes(b.lime())
    out = tmp_path / "o.csv"
    main([str(p), "--csv", str(out), "-q"])
    assert "'=cmd|calc.dll" in out.read_text(encoding="utf-8-sig")
