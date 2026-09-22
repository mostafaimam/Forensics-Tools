from __future__ import annotations

import json

import pytest

from memory_consoles.carve import _looks_command_like, carve_command_like
from memory_consoles.procscan import scan
from memory_consoles.loader import MemoryImage
from memory_consoles.collect import scan_image
from memory_consoles.cli import main


def _write_image(tmp_path, data: bytes):
    p = tmp_path / "mem.raw"
    p.write_bytes(data)
    return p


def _proc_block(name: bytes, padded_field_len: int = 15) -> bytes:
    field = name.ljust(padded_field_len, b"\x00")
    return b"Proc" + b"\x00" * 16 + field + b"\x00" * 32


def test_procscan_finds_conhost(tmp_path):
    data = b"\x11" * 4096 + _proc_block(b"conhost.exe") + b"\x22" * 4096
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert len(hits) == 1
    assert hits[0].name == "conhost.exe"


def test_procscan_finds_powershell(tmp_path):
    data = _proc_block(b"powershell.exe")
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert hits and hits[0].name == "powershell.exe"


def test_procscan_rejects_coincidental_longer_name(tmp_path):
    # "conhost.exemplary" should NOT be treated as "conhost.exe" - the
    # boundary check requires the byte right after a short match to be
    # NUL (a real 15-byte NUL-padded ImageFileName field), not another
    # letter continuing the string
    data = b"Proc" + b"\x00" * 16 + b"conhost.exemplary_process_name!!"
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert hits == []


def test_procscan_ignores_unrelated_process(tmp_path):
    data = _proc_block(b"notepad.exe")
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert hits == []


def test_procscan_distinguishes_adjacent_processes(tmp_path):
    # regression: an earlier bug picked whichever name occurred first
    # in _NAMES's own iteration order, not whichever occurred first
    # in memory - a "Proc" tag's window could reach an adjacent
    # process's own block and report that process's name instead,
    # confirmed via the GUI screenshot before this was fixed.
    data = (_proc_block(b"powershell.exe") + b"\x11" * 40 +
           _proc_block(b"conhost.exe"))
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    names = [h.name for h in hits]
    assert names == ["powershell.exe", "conhost.exe"]


def test_procscan_no_proc_tag_no_hits(tmp_path):
    data = b"\x11" * 4096
    p = _write_image(tmp_path, data)
    with MemoryImage(str(p)) as img:
        hits = scan(img)
    assert hits == []


def test_looks_command_like_positive():
    assert _looks_command_like(r"cmd.exe /c whoami /all")
    assert _looks_command_like(r"powershell.exe -NoProfile -Command X")
    assert _looks_command_like(r"C:\Windows\System32\net.exe use")


def test_looks_command_like_negative():
    assert not _looks_command_like("hi")            # too short
    assert not _looks_command_like("1234567890")     # no space/path/flag
    assert not _looks_command_like("   ")            # not alpha-led


def test_carve_command_like_finds_embedded_command():
    data = b"\x00\x01\x02\x03" + \
        "cmd.exe /c dir C:\\Users".encode("ascii") + b"\x04\x05\x06"
    found = carve_command_like(data)
    assert any("cmd.exe /c dir" in s for s in found)


def test_carve_command_like_skips_plain_noise():
    data = bytes((i * 41 + 3) % 256 for i in range(2048))
    found = carve_command_like(data)
    assert found == []


def test_collect_end_to_end(tmp_path):
    data = (_proc_block(b"powershell.exe") + b"\x00" * 64 +
           "powershell.exe -Command Get-Process".encode("ascii"))
    p = _write_image(tmp_path, data)
    res = scan_image(str(p))
    kinds = {r["kind"] for r in res.rows}
    assert "process" in kinds
    assert "candidate_text" in kinds


def test_collect_warns_when_no_process_found(tmp_path):
    data = b"\x11" * 4096
    p = _write_image(tmp_path, data)
    res = scan_image(str(p))
    assert res.warnings


def test_cli_csv_json(tmp_path):
    data = _proc_block(b"conhost.exe")
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
    from memory_consoles.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
