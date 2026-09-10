from __future__ import annotations

import json

import pytest

from windows_shellbags import bagmru as B
from windows_shellbags import shellitems as SI
from windows_shellbags.analyze import analyze
from windows_shellbags.cli import main

import _synth as S
import _hive_synth as H


def _bags(tmp_path):
    S.build_root(tmp_path)
    return {b.path: b for b in analyze([str(tmp_path)]).bags}


def test_shell_item_parsers():
    di = SI.parse_idlist(H.dir_item("tools", "tools", mft_entry=51201,
                                    mft_seq=4))[0]
    assert di["type"] == "directory"
    assert di["mft_entry"] == 51201 and di["mft_sequence"] == 4
    assert di.get("long_name") == "tools"
    dr = SI.parse_idlist(H.drive_item("C:\\"))[0]
    assert dr["type"] == "drive" and dr["name"] == "C:\\"
    gi = SI.parse_idlist(H.guid_item(H.THIS_PC))[0]
    assert gi["type"] == "known-folder" and gi["name"] == "This PC"


def test_bagmru_walk_from_hive():
    res = B.from_hive_bytes(H.build_usrclass())
    assert res.hive_kind == "UsrClass.dat"
    paths = {b.path for b in res.bags}
    assert "C:\\" in paths
    assert "C:\\Users" in paths
    assert "C:\\Users\\attacker" in paths
    assert "C:\\Users\\attacker\\Downloads\\tools" in paths
    assert "\\\\FILESRV\\backup" in paths


def test_timestamps_and_mft(tmp_path):
    bags = _bags(tmp_path)
    users = bags["C:\\Users"]
    assert users.last_interacted if hasattr(users, "last_interacted") \
        else users.last_written        # key last-written present
    assert users.mft_entry == "1200"
    tools = bags["C:\\Users\\attacker\\Downloads\\tools"]
    # DOS timestamps are local (no Z)
    assert tools.modified and not tools.modified.endswith("Z")


def test_mru_position(tmp_path):
    bags = _bags(tmp_path)
    # Users key MRUListEx was [1, 0] -> slot 1 (attacker) is most recent
    assert bags["C:\\Users\\attacker"].mru_position == 0
    assert bags["C:\\Users\\report.zip"].mru_position == 1


def test_flags(tmp_path):
    bags = _bags(tmp_path)
    net = bags["\\\\FILESRV\\backup"]
    assert any("network / UNC path browsed" in n for n in net.notable)

    atk = bags["C:\\Users\\attacker"]
    assert any("another user's profile browsed (attacker)" in n
               for n in atk.notable)

    tools = bags["C:\\Users\\attacker\\Downloads\\tools"]
    assert any("offensive tooling" in n for n in tools.notable)

    zp = bags["C:\\Users\\report.zip"]
    assert any("archive" in n for n in zp.notable)


def test_cli_csv_json_filters(tmp_path):
    S.build_root(tmp_path)
    csv_p = tmp_path / "s.csv"
    js_p = tmp_path / "s.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and len(data) >= 6

    main([str(tmp_path), "--type", "network", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["item_type"] == "network" for r in got)

    main([str(tmp_path), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_direct_hive_file(tmp_path):
    hive = S.write_hive(tmp_path / "UsrClass.dat")
    js_p = tmp_path / "s.json"
    rc = main([str(hive), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) >= 6


def test_no_bagmru(tmp_path):
    (tmp_path / "empty.dat").write_bytes(b"regf" + b"\x00" * 5000)
    rc = main([str(tmp_path / "empty.dat"), "-q"])
    assert rc == 1


def test_csv_injection_guard():
    from windows_shellbags.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
