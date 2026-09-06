from _synth import build_sample_hive
from windows_registry.hive import HiveError, RegistryHive, to_text


def _hive():
    return RegistryHive(build_sample_hive())


def test_base_block():
    h = _hive()
    assert not h.base.is_dirty
    assert h.base.major_version == 1 and h.base.minor_version == 3
    assert h.base.last_written.year == 2024


def test_root_and_walk():
    h = _hive()
    root = h.root()
    assert root.name == "ROOT"
    paths = {k.path for k in h.walk()}
    assert "ROOT\\Software" in paths
    assert "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in paths
    assert "ROOT\\TestKey" in paths


def test_get_path_case_insensitive():
    h = _hive()
    k = h.get("software\\microsoft\\windows\\currentversion\\RUN")
    assert k is not None and k.name == "Run"
    assert h.get("Software\\Nope") is None


def test_values_decode():
    h = _hive()
    tk = h.get("TestKey")
    vals = {v.name: v for v in tk.values()}
    assert vals["Count"].data == 7
    assert vals["Count"].type_name == "REG_DWORD"
    assert vals["Count"].resident
    assert vals["Note"].data == "hello world"
    assert vals["Note"].type_name == "REG_SZ"


def test_run_key_value():
    h = _hive()
    run = h.get("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    v = run.values()[0]
    assert v.name == "OneDrive"
    assert v.data == "C:\\Users\\a\\OneDrive.exe"
    assert run.last_written.month == 4


def test_recover_deleted_key():
    h = _hive()
    recovered = [k.node.name for k in h.recover_deleted()]
    assert "DeletedSecretKey" in recovered


def test_not_a_hive():
    import pytest
    with pytest.raises(HiveError):
        RegistryHive(b"PK\x03\x04 not a hive at all, padding........")
