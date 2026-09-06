import json
import struct

from _synth import lime_dump, raw_dump, winkdump
from memory_image.cli import main
from memory_image.loader import MemoryImage


def test_info(tmp_path, capsys):
    blob, _ = winkdump([(0x1, 0x10)])
    p = tmp_path / "MEMORY.DMP"
    p.write_bytes(blob)
    rc = main(["info", str(p), "--json", str(tmp_path / "i.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "format        : winkdump" in out and "windows" in out
    j = json.loads((tmp_path / "i.json").read_text())
    assert j["os_hints"]["arch"] == "x64"


def test_ranges_json(tmp_path):
    blob, _ = lime_dump([(0x1000, 0x2000), (0x9000, 0x1000)])
    p = tmp_path / "m.lime"
    p.write_bytes(blob)
    out = tmp_path / "r.json"
    assert main(["ranges", str(p), "--json", str(out)]) == 0
    runs = json.loads(out.read_text())
    assert [r["phys_start"] for r in runs] == [0x1000, 0x9000]


def test_convert_lime_to_raw(tmp_path):
    blob, data = lime_dump([(0x0, 0x1000), (0x4000, 0x1000)])
    p = tmp_path / "m.lime"
    p.write_bytes(blob)
    out = tmp_path / "m.raw"
    assert main(["convert", str(p), str(out), "--format", "raw", "-q"]) == 0
    assert out.read_bytes() == data[0x0] + data[0x4000]


def test_convert_raw_to_lime_roundtrips(tmp_path):
    p = tmp_path / "m.raw"
    p.write_bytes(raw_dump(0x3000))
    lp = tmp_path / "m.lime"
    main(["convert", str(p), str(lp), "--format", "lime", "-q"])
    magic = struct.unpack_from("<I", lp.read_bytes(), 0)[0]
    assert magic == 0x4C694D45
    with MemoryImage(lp) as img:
        assert img.read_physical(0, 0x3000) == p.read_bytes()


def test_convert_padded_has_offsets(tmp_path):
    blob, data = lime_dump([(0x1000, 0x1000), (0x8000, 0x1000)])
    p = tmp_path / "m.lime"
    p.write_bytes(blob)
    out = tmp_path / "m.padded"
    main(["convert", str(p), str(out), "--format", "padded", "-q"])
    b = out.read_bytes()
    assert b[0x1000:0x2000] == data[0x1000]
    assert b[0x8000:0x9000] == data[0x8000]
    assert b[0x2000:0x8000] == b"\x00" * 0x6000


def test_carve_and_read(tmp_path, capsys):
    blob, data = lime_dump([(0x1000, 0x4000)])
    p = tmp_path / "m.lime"
    p.write_bytes(blob)
    out = tmp_path / "region.bin"
    main(["carve", str(p), "--physical", "0x2000", "--size", "0x100",
          "--out", str(out)])
    assert out.read_bytes() == data[0x1000][0x1000:0x1100]

    main(["read", str(p), "--physical", "0x1000", "--size", "16"])
    assert "0x000000001000" in capsys.readouterr().out


def test_missing(tmp_path):
    assert main(["info", str(tmp_path / "nope")]) == 2
