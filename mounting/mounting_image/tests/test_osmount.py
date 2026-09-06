import json
from unittest import mock

from _synth import make_mbr_disk
from mounting_image import osmount
from mounting_image.osmount import MountResult


def test_free_drive_letters_excludes_used():
    with mock.patch.object(osmount, "_ps", return_value="C,E,F"):
        free = osmount.free_drive_letters()
    assert "D" in free and "G" in free
    assert "E" not in free and "F" not in free
    assert "C" not in free


def test_registry_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(osmount, "_REGISTRY", tmp_path / "drives.json")
    res = MountResult(backend="windows", image_file=str(tmp_path / "x.vhd"),
                      handle="3",
                      volumes=[{"name": "X:", "access": "ro", "size": 100}],
                      temp_image=True)
    mid = osmount.register(res, "case.E01", None)
    rows = osmount.sessions()
    assert len(rows) == 1 and rows[0]["id"] == mid
    assert rows[0]["volumes"][0]["name"] == "X:"

    # look up by drive letter
    gone = osmount.deregister("X:")
    assert gone and gone["id"] == mid
    assert osmount.sessions() == []


def test_unmount_dispatch_windows(tmp_path):
    entry = {"backend": "windows", "image_file": str(tmp_path / "a.vhd"),
             "temp_image": True}
    (tmp_path / "a.vhd").write_bytes(b"x")
    with mock.patch.object(osmount, "unmount_windows") as uw:
        osmount.unmount(entry)
    uw.assert_called_once()
    assert not (tmp_path / "a.vhd").exists()          # temp image cleaned


def test_cli_mount_uses_backend(tmp_path, monkeypatch, capsys):
    from mounting_image.cli import main
    monkeypatch.setattr(osmount, "_REGISTRY", tmp_path / "drives.json")
    src = tmp_path / "disk.raw"
    src.write_bytes(make_mbr_disk())

    fake = MountResult(backend="windows", image_file=str(tmp_path / "t.vhd"),
                       handle="4",
                       volumes=[{"name": "Y:", "access": "ro", "size": 4096}])
    with mock.patch.object(osmount, "current_backend", return_value="windows"), \
         mock.patch.object(osmount, "mount_windows",
                           return_value=fake) as mw:
        rc = main(["mount", str(src), "--letter", "Y", "-q"])
    assert rc == 0
    assert "Y:" in capsys.readouterr().out
    # a temp VHD was materialised and passed to mount_windows
    called_vhd = mw.call_args[0][0]
    assert called_vhd.endswith(".vhd")

    rows = json.loads((tmp_path / "drives.json").read_text())
    assert rows[0]["volumes"][0]["name"] == "Y:"

    with mock.patch.object(osmount, "unmount_windows"):
        rc = main(["unmount-drive", "Y:"])
    assert rc == 0
    assert json.loads((tmp_path / "drives.json").read_text()) == []


def test_cli_mount_unsupported_platform(tmp_path, monkeypatch):
    from mounting_image.cli import main
    src = tmp_path / "d.raw"
    src.write_bytes(make_mbr_disk())
    with mock.patch.object(osmount, "current_backend", return_value=""):
        assert main(["mount", str(src), "-q"]) == 2
