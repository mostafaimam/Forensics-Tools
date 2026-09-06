import struct

from _synth import build_log, build_primary
from windows_reglog.cli import main


def test_info(tmp_path, capsys):
    (tmp_path / "SYSTEM").write_bytes(build_primary(6, 5))
    (tmp_path / "SYSTEM.LOG1").write_bytes(build_log(5, 0, b"hbin\x00\x00PAGE5"))
    rc = main(["--info", str(tmp_path / "SYSTEM")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DIRTY" in out
    assert "SYSTEM.LOG1" in out


def test_replay_to_output(tmp_path):
    (tmp_path / "NTUSER.DAT").write_bytes(build_primary(6, 4, marker=b"OLD"))
    (tmp_path / "NTUSER.DAT.LOG1").write_bytes(
        build_log(4, 0, b"hbin" + b"\x00" * 12 + b"NEWDATA"))
    (tmp_path / "NTUSER.DAT.LOG2").write_bytes(
        build_log(5, 0, b"hbin" + b"\x00" * 12 + b"NEWERDATA"))
    out = tmp_path / "clean.dat"
    rc = main([str(tmp_path / "NTUSER.DAT"), "-o", str(out), "-q"])
    assert rc == 0
    data = out.read_bytes()
    s1, s2 = struct.unpack_from("<II", data, 4)
    assert s1 == s2 == 6
    assert b"NEWERDATA" in data[4096:8192]


def test_clean_hive_copies_through(tmp_path):
    (tmp_path / "h").write_bytes(build_primary(9, 9))
    out = tmp_path / "o"
    rc = main([str(tmp_path / "h"), "-o", str(out), "-q"])
    assert rc == 0
    assert out.read_bytes() == build_primary(9, 9)


def test_missing_hive(tmp_path):
    assert main([str(tmp_path / "nope")]) == 2


def test_explicit_logs(tmp_path):
    (tmp_path / "SAM").write_bytes(build_primary(3, 2))
    lg = tmp_path / "sam_log1.bin"
    lg.write_bytes(build_log(2, 0, b"hbin\x00\x00X"))
    out = tmp_path / "sam.clean"
    rc = main([str(tmp_path / "SAM"), "--log", str(lg), "-o", str(out), "-q"])
    assert rc == 0
    assert struct.unpack_from("<II", out.read_bytes(), 4) == (3, 3)
