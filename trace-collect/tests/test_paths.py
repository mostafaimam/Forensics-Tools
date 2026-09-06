import os

import pytest

from trace_collect.paths import (
    HostContext,
    UnknownVariableError,
    expand_path,
    long_path,
    strip_long_prefix,
)


def _ctx(tmp_path):
    users = tmp_path / "Users"
    (users / "alice").mkdir(parents=True)
    (users / "bob").mkdir(parents=True)
    return HostContext(
        system_drive=str(tmp_path) + os.sep,
        system_root=str(tmp_path / "Windows"),
        program_data=str(tmp_path / "ProgramData"),
        users_dir=str(users),
        user_profiles=(str(users / "alice"), str(users / "bob")),
    )


def test_expand_simple_variable(tmp_path):
    ctx = _ctx(tmp_path)
    out = expand_path("%SystemRoot%/Prefetch/x.pf", ctx)
    assert out == [os.path.normpath(str(tmp_path / "Windows" / "Prefetch" / "x.pf"))]


def test_expand_unknown_variable(tmp_path):
    with pytest.raises(UnknownVariableError):
        expand_path("%Nope%/x", _ctx(tmp_path))


def test_userprofiles_fan_out(tmp_path):
    ctx = _ctx(tmp_path)
    out = expand_path("%UserProfiles%/NTUSER.DAT", ctx)
    assert len(out) == 2
    assert any("alice" in p for p in out)
    assert any("bob" in p for p in out)


def test_home_token_is_case_insensitive(tmp_path):
    ctx = _ctx(tmp_path)
    out = expand_path("%home%/.bash_history", ctx)
    assert len(out) == 2


@pytest.mark.skipif(os.name != "nt", reason="windows long path")
def test_long_path_roundtrip():
    p = "C:\\Windows\\System32\\config\\SYSTEM"
    lp = long_path(p)
    assert lp.startswith("\\\\?\\")
    assert strip_long_prefix(lp) == p
