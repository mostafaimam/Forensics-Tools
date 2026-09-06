import textwrap

import pytest

from acquisition_collect.targets import TargetError, load_builtin, load_target_file


def test_builtin_targets_load_and_are_unique():
    ts = load_builtin()
    assert len(ts.targets) > 30
    ids = [t.id for t in ts.targets]
    assert len(ids) == len(set(ids))
    for os_name in ("windows", "linux", "macos"):
        assert ts.for_os(os_name), f"no targets for {os_name}"


def test_builtin_every_target_has_paths_and_valid_os():
    for t in load_builtin().targets:
        assert t.paths
        assert t.os <= {"windows", "linux", "macos"}


def test_select_by_category_and_id():
    ts = load_builtin()
    fs = ts.select("windows", categories=["FileSystem"])
    assert fs and all(t.category == "FileSystem" for t in fs)
    one = ts.select("windows", ids=["windows-prefetch"])
    assert [t.id for t in one] == ["windows-prefetch"]


def test_select_unknown_id_raises():
    with pytest.raises(TargetError):
        load_builtin().select("windows", ids=["does-not-exist"])


def test_multi_target_file(tmp_path):
    f = tmp_path / "x.toml"
    f.write_text(textwrap.dedent("""
        [[target]]
        id = "t1"
        name = "One"
        os = ["linux"]
        paths = [{ path = "/etc/hosts" }]

        [[target]]
        id = "t2"
        name = "Two"
        os = ["linux"]
        paths = [{ path = "/etc/passwd" }]
    """))
    got = load_target_file(f)
    assert {t.id for t in got} == {"t1", "t2"}


def test_bad_os_value(tmp_path):
    f = tmp_path / "bad.toml"
    f.write_text('id="x"\nname="x"\nos=["plan9"]\npaths=[{path="/x"}]\n')
    with pytest.raises(TargetError):
        load_target_file(f)
