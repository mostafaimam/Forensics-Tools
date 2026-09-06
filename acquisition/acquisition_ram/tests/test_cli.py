import json

from _synth import make_iomem, make_kcore, phys_ram, windows_root
from acquisition_ram.cli import main


def _kcore(tmp_path, ranges):
    ram = phys_ram(0x40000)
    (tmp_path / "kcore").write_bytes(make_kcore(ram))
    (tmp_path / "iomem").write_text(make_iomem(ranges))
    return ram


def test_info_linux_offline(tmp_path, capsys):
    _kcore(tmp_path, [(0x1000, 0x20000)])
    rc = main(["info", "--kcore", str(tmp_path / "kcore"),
               "--iomem", str(tmp_path / "iomem")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "kcore readable : yes" in out and "ready to capture: YES" in out


def test_capture_linux_offline_lime(tmp_path):
    ram = _kcore(tmp_path, [(0x1000, 0x8000), (0x10000, 0x20000)])
    out = tmp_path / "mem.lime"
    rc = main(["capture", str(out), "--kcore", str(tmp_path / "kcore"),
               "--iomem", str(tmp_path / "iomem"), "--case", "2026-9", "-q"])
    assert rc == 0
    assert out.exists()
    man = json.loads((tmp_path / "mem.lime.json").read_text())
    assert man["method"] == "linux-kcore"
    assert man["metadata"]["case_number"] == "2026-9"
    assert len(man["ranges"]) == 2
    assert man["outputs"][0]["hashes"]["sha256"]
    log = (tmp_path / "mem.lime.txt").read_text()
    assert "RAM ranges" in log and "SHA256" in log


def test_capture_raw_writes_range_map(tmp_path):
    _kcore(tmp_path, [(0x1000, 0x4000)])
    out = tmp_path / "m.raw"
    main(["capture", str(out), "--kcore", str(tmp_path / "kcore"),
          "--iomem", str(tmp_path / "iomem"), "--format", "raw", "-q"])
    ranges = json.loads((tmp_path / "m.raw.ranges.json").read_text())
    assert ranges[0]["start"] == 0x1000


def test_capture_windows_source(tmp_path, capsys):
    root = windows_root(tmp_path)
    out = tmp_path / "ram_files"
    rc = main(["capture", str(out), "--source", str(root), "--os", "windows",
               "-q"])
    assert rc == 0
    assert (out / "pagefile.sys").exists()
    man = json.loads((out / "acquisition_ram.json").read_text())
    assert man["method"] == "windows-files"
    names = {o["name"] for o in man["outputs"]}
    assert "hiberfil.sys" in names and "MEMORY.DMP" in names


def test_info_windows_source(tmp_path, capsys):
    root = windows_root(tmp_path)
    rc = main(["info", "--source", str(root), "--os", "windows"])
    assert rc == 0
    assert "pagefile.sys" in capsys.readouterr().out


def test_capture_offline_missing_kcore_fails(tmp_path, capsys):
    rc = main(["capture", str(tmp_path / "x.lime"),
               "--kcore", str(tmp_path / "no-kcore"),
               "--iomem", str(tmp_path / "no-iomem"), "-q"])
    assert rc == 2
    assert "cannot" in capsys.readouterr().err.lower()


def test_methods():
    assert main(["methods"]) == 0
