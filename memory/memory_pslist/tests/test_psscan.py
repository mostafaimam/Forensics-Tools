from datetime import datetime

from _synth import eprocess, lime_with
from memory_pslist.loader import MemoryImage
from memory_pslist.psscan import ft_to_iso, scan


def _img(tmp_path, blobs):
    p = tmp_path / "mem.lime"
    p.write_bytes(lime_with(blobs))
    return MemoryImage(p)


def test_finds_running_process(tmp_path):
    img = _img(tmp_path, [
        eprocess("lsass.exe", 764, 596, datetime(2026, 9, 1, 8, 0, 0)),
    ])
    procs = scan(img)
    p = next(x for x in procs if x.name == "lsass.exe")
    assert p.pid == 764
    assert p.create_time.startswith("2026-09-01T08:00")
    assert not p.exited and p.exit_time == ""
    assert p.confidence in ("medium", "high")


def test_finds_terminated_process(tmp_path):
    img = _img(tmp_path, [
        eprocess("evil.exe", 4321, 764, datetime(2026, 9, 1, 9, 0, 0),
                 datetime(2026, 9, 1, 9, 5, 0)),
    ])
    p = next(x for x in scan(img) if x.name == "evil.exe")
    assert p.exited and p.exit_time.startswith("2026-09-01T09:05")


def test_protected_pool_tag(tmp_path):
    img = _img(tmp_path, [
        eprocess("System", 4, 0, datetime(2026, 9, 1, 7, 0, 0), protected=True),
    ])
    p = next(x for x in scan(img) if x.name == "System")
    assert "protected" in p.pool_tag


def test_dedupe_and_multiple(tmp_path):
    now = datetime(2026, 9, 1, 8, 0, 0)
    img = _img(tmp_path, [
        eprocess("svchost.exe", 1000, 764, now),
        eprocess("svchost.exe", 1000, 764, now),   # duplicate copy in RAM
        eprocess("explorer.exe", 2200, 2100, now),
    ])
    names = sorted(p.name for p in scan(img))
    assert names.count("svchost.exe") == 1
    assert "explorer.exe" in names


def test_ft_to_iso_rejects_garbage():
    assert ft_to_iso(0) == ""
    assert ft_to_iso(0xFFFFFFFFFFFFFFFF) == ""
    assert ft_to_iso(1) == ""
