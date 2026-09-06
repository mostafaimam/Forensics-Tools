import csv
import json
import uuid

from _synth import build_lnk
from windows_lnk.cli import main


def test_csv(tmp_path):
    (tmp_path / "a.lnk").write_bytes(build_lnk(
        target=r"C:\tools\mimikatz.exe", machine="ATTACK-BOX",
        obj_uuid=uuid.uuid1(node=0x001122334455)))
    out = tmp_path / "o.csv"
    rc = main([str(tmp_path / "a.lnk"), "--csv", str(out), "-q"])
    assert rc == 0
    r = list(csv.DictReader(out.open(encoding="utf-8-sig")))[0]
    assert r["target_path"] == r"C:\tools\mimikatz.exe"
    assert r["machine_id"] == "ATTACK-BOX"
    assert r["mac_address"] == "00:11:22:33:44:55"
    assert r["target_modified_utc"].endswith("Z")


def test_json_and_directory(tmp_path):
    d = tmp_path / "Recent"
    d.mkdir()
    (d / "1.lnk").write_bytes(build_lnk(target=r"C:\x\1.txt"))
    (d / "2.lnk").write_bytes(build_lnk(target=r"C:\x\2.txt"))
    out = tmp_path / "all.json"
    rc = main([str(d), "--json", str(out), "-q"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert {o["target_path"] for o in data} == {r"C:\x\1.txt", r"C:\x\2.txt"}
    assert all("tracker" in o for o in data)


def test_bad_lnk_reported(tmp_path):
    (tmp_path / "bad.lnk").write_bytes(b"not a lnk file at all")
    (tmp_path / "good.lnk").write_bytes(build_lnk())
    out = tmp_path / "o.csv"
    rc = main([str(tmp_path), "--csv", str(out), "-q"])
    assert rc == 0                       # one good file still parsed
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 1


def test_all_bad_returns_1(tmp_path):
    (tmp_path / "x.lnk").write_bytes(b"junk")
    assert main([str(tmp_path / "x.lnk"), "-q"]) == 1
