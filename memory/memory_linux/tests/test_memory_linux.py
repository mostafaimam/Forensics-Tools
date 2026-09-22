from __future__ import annotations

import json

import pytest

import _synth as S

from memory_linux.pslist import (Profile, ProfileError,
                                 carve_comm_candidates, walk_task_list)
from memory_linux.loader import MemoryImage
from memory_linux.collect import scan_image
from memory_linux.cli import main


def test_profile_load(tmp_path):
    img_path, profile_path = S.build(tmp_path, ["swapper", "systemd",
                                                "bash"], [0, 1, 4242])
    profile = Profile.load(str(profile_path))
    assert profile.direct_map_base == S.DIRECT_MAP_BASE
    assert profile.tasks_offset == S.TASKS_OFFSET


def test_profile_load_missing_field(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"direct_map_base": 0}))
    with pytest.raises(ProfileError):
        Profile.load(str(p))


def test_walk_task_list_recovers_chain(tmp_path):
    # comms[0] is init_task (the walk's anchor) - only comms[1:] are
    # returned, matching real init_task-as-sentinel convention
    img_path, profile_path = S.build(
        tmp_path, ["swapper", "systemd", "bash"], [0, 1, 4242])
    profile = Profile.load(str(profile_path))
    with MemoryImage(str(img_path)) as img:
        tasks = walk_task_list(img, profile)
    assert [t.comm for t in tasks] == ["systemd", "bash"]
    assert [t.pid for t in tasks] == [1, 4242]


def test_walk_task_list_single_entry_loop(tmp_path):
    img_path, profile_path = S.build(tmp_path, ["swapper"], [0])
    profile = Profile.load(str(profile_path))
    with MemoryImage(str(img_path)) as img:
        tasks = walk_task_list(img, profile)
    assert tasks == []   # only init_task itself, nothing else in the list


def test_walk_task_list_wrong_direct_map_base_raises(tmp_path):
    img_path, profile_path = S.build(tmp_path, ["swapper", "sshd"], [0, 99])
    profile = Profile.load(str(profile_path))
    profile.direct_map_base += 0x1000000000  # deliberately wrong
    with MemoryImage(str(img_path)) as img:
        with pytest.raises(ProfileError):
            walk_task_list(img, profile)


def test_carve_comm_candidates_finds_null_terminated_strings(tmp_path):
    data = b"\x01\x02bash\x00\x03\x04systemd\x00\xff\xff"
    p = tmp_path / "mem.raw"
    p.write_bytes(data)
    with MemoryImage(str(p)) as img:
        found = carve_comm_candidates(img)
    assert "bash" in found
    assert "systemd" in found


def test_collect_with_profile(tmp_path):
    img_path, profile_path = S.build(
        tmp_path, ["swapper", "cron", "nginx"], [0, 88, 1010])
    res = scan_image(str(img_path), profile_path=str(profile_path))
    assert not res.warnings
    assert {r["comm"] for r in res.rows} == {"cron", "nginx"}
    assert all(r["method"] == "task-list-walk" for r in res.rows)


def test_collect_without_profile_falls_back(tmp_path):
    p = tmp_path / "mem.raw"
    p.write_bytes(b"\x00bash\x00\x00systemd\x00\x11" * 4)
    res = scan_image(str(p))
    assert res.warnings
    assert any(r["method"] == "heuristic-carve" for r in res.rows)


def test_cli_csv_json(tmp_path):
    img_path, profile_path = S.build(tmp_path, ["swapper", "init"], [0, 1])
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(img_path), "--profile", str(profile_path), "--csv",
              str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from memory_linux.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
