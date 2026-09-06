from _synth import macos_root, windows_root
from acquisition_ram.capture import collect_files
from acquisition_ram.mac import enumerate_sources as mac_sources
from acquisition_ram.win import enumerate_sources as win_sources


def test_windows_enumerate(tmp_path):
    root = windows_root(tmp_path)
    got = {s["category"] for s in win_sources(str(root))}
    assert {"page file", "hibernation", "swap file", "crash dump",
            "minidump"} <= got
    # a --source scan never reports files as locked
    assert all(not s["locked"] for s in win_sources(str(root)))


def test_macos_enumerate(tmp_path):
    root = macos_root(tmp_path)
    cats = [s["category"] for s in mac_sources(str(root))]
    assert cats.count("swap file") == 2 and "hibernation" in cats


def test_collect_files_copies_and_hashes(tmp_path):
    import hashlib
    root = windows_root(tmp_path)
    out = tmp_path / "ram"
    outs = collect_files(win_sources(str(root)), out)
    page = next(o for o in outs if o.name == "pagefile.sys")
    assert page.size == len(b"PAGE" * 4096)
    assert page.hashes["sha256"] == hashlib.sha256(
        (root / "pagefile.sys").read_bytes()).hexdigest()
    assert (out / "pagefile.sys").read_bytes() == (root / "pagefile.sys").read_bytes()


def test_collect_files_only_filter(tmp_path):
    root = windows_root(tmp_path)
    outs = collect_files(win_sources(str(root)), tmp_path / "o",
                         only={"hibernation"})
    assert [o.name for o in outs] == ["hiberfil.sys"]
