from __future__ import annotations

import json

import pytest

import _synth as S

from memory_macos.pslist import (Profile, ProfileError,
                                 carve_comm_candidates, walk_allproc)
from memory_macos.loader import MemoryImage
from memory_macos.collect import scan_image
from memory_macos.cli import main


def test_profile_load(tmp_path):
    _img, profile_path = S.build(tmp_path, ["kernel_task", "launchd"],
                                 [0, 1])
    profile = Profile.load(str(profile_path))
    assert profile.direct_map_base == S.DIRECT_MAP_BASE
    assert profile.p_list_next_offset == S.P_LIST_NEXT_OFFSET


def test_profile_load_missing_field(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"direct_map_base": 0}))
    with pytest.raises(ProfileError):
        Profile.load(str(p))


def test_walk_allproc_recovers_full_chain(tmp_path):
    # unlike Linux's circular tasks list (which excludes init_task),
    # BSD's NULL-terminated LIST walk includes every proc from
    # allproc_first_va onward, including the first
    img_path, profile_path = S.build(
        tmp_path, ["kernel_task", "launchd", "WindowServer", "Finder"],
        [0, 1, 88, 501])
    profile = Profile.load(str(profile_path))
    with MemoryImage(str(img_path)) as img:
        procs = walk_allproc(img, profile)
    assert [pr.comm for pr in procs] == \
        ["kernel_task", "launchd", "WindowServer", "Finder"]
    assert [pr.pid for pr in procs] == [0, 1, 88, 501]


def test_walk_allproc_single_entry_terminates(tmp_path):
    img_path, profile_path = S.build(tmp_path, ["kernel_task"], [0])
    profile = Profile.load(str(profile_path))
    with MemoryImage(str(img_path)) as img:
        procs = walk_allproc(img, profile)
    assert len(procs) == 1
    assert procs[0].comm == "kernel_task"


def test_walk_allproc_wrong_direct_map_base_raises(tmp_path):
    img_path, profile_path = S.build(tmp_path, ["kernel_task", "sshd"],
                                     [0, 77])
    profile = Profile.load(str(profile_path))
    profile.direct_map_base += 0x1000000000  # deliberately wrong
    with MemoryImage(str(img_path)) as img:
        with pytest.raises(ProfileError):
            walk_allproc(img, profile)


def test_carve_comm_candidates_finds_null_terminated_strings(tmp_path):
    data = b"\x01\x02Finder\x00\x03\x04launchd\x00\xff\xff"
    p = tmp_path / "mem.raw"
    p.write_bytes(data)
    with MemoryImage(str(p)) as img:
        found = carve_comm_candidates(img)
    assert "Finder" in found
    assert "launchd" in found


def test_collect_with_profile(tmp_path):
    img_path, profile_path = S.build(
        tmp_path, ["kernel_task", "cfprefsd", "Safari"], [0, 55, 909])
    res = scan_image(str(img_path), profile_path=str(profile_path))
    assert not res.warnings
    assert {r["comm"] for r in res.rows} == \
        {"kernel_task", "cfprefsd", "Safari"}
    assert all(r["method"] == "allproc-walk" for r in res.rows)


def test_collect_without_profile_falls_back(tmp_path):
    p = tmp_path / "mem.raw"
    p.write_bytes(b"\x00Finder\x00\x00Safari\x00\x11" * 4)
    res = scan_image(str(p))
    assert res.warnings
    assert any(r["method"] == "heuristic-carve" for r in res.rows)


def test_cli_csv_json(tmp_path):
    img_path, profile_path = S.build(tmp_path, ["kernel_task", "bash"],
                                     [0, 1])
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
    from memory_macos.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
