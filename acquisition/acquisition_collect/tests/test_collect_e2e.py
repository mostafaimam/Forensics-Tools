"""End-to-end: build a fake source tree, collect it, verify manifest + hashes."""

import csv
import hashlib
import os
import textwrap
import zipfile
from pathlib import Path

from acquisition_collect.cli import main
from acquisition_collect.paths import long_path


def _make_source(root: Path) -> dict[str, bytes]:
    files = {
        "Windows/System32/winevt/Logs/System.evtx": b"EVTX-DATA-1" * 100,
        "Windows/System32/winevt/Logs/Security.evtx": b"EVTX-DATA-2" * 50,
        "Windows/Prefetch/CALC.EXE-1234.pf": b"PF" * 10,
        "Users/alice/NTUSER.DAT": b"REGF" + b"\x00" * 500,
        "Users/bob/NTUSER.DAT": b"REGF" + b"\x11" * 500,
    }
    out = {}
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        out[rel] = data
    return out


def _targets_dir(tmp_path: Path) -> Path:
    d = tmp_path / "targets"
    d.mkdir()
    (d / "t.toml").write_text(textwrap.dedent("""
        [[target]]
        id = "evtx"
        name = "Event logs"
        category = "EventLogs"
        os = ["windows"]
        paths = [{ path = '%SystemRoot%\\\\System32\\\\winevt\\\\Logs\\\\*.evtx' }]

        [[target]]
        id = "prefetch"
        name = "Prefetch"
        category = "ProgramExecution"
        os = ["windows"]
        paths = [{ path = '%SystemRoot%\\\\Prefetch\\\\*.pf' }]

        [[target]]
        id = "reguser"
        name = "User hives"
        category = "Registry"
        os = ["windows"]
        paths = [{ path = '%UserProfiles%\\\\NTUSER.DAT' }]
    """))
    return d


def test_dir_collection(tmp_path):
    src = tmp_path / "image_c"
    src.mkdir()
    made = _make_source(src)
    dest = tmp_path / "out"

    rc = main([
        "-d", str(dest), "--source", str(src), "--os", "windows",
        "--target-dir", str(_targets_dir(tmp_path)),
        "--hash", "md5,sha256", "--verbose",
    ])
    assert rc == 0

    run_dirs = list(dest.glob("acquisition_collect_*"))
    assert len(run_dirs) == 1
    run = run_dirs[0]

    rows = list(csv.DictReader((run / "acquisition_collect_manifest.csv").open(encoding="utf-8-sig")))
    assert len(rows) == len(made)

    by_name = {Path(r["source_path"]).name: r for r in rows}
    assert by_name["System.evtx"]["md5"] == hashlib.md5(made[
        "Windows/System32/winevt/Logs/System.evtx"]).hexdigest()
    assert by_name["System.evtx"]["sha256"] == hashlib.sha256(made[
        "Windows/System32/winevt/Logs/System.evtx"]).hexdigest()

    # both user profiles collected (alice + bob)
    ntuser_rows = [r for r in rows if Path(r["source_path"]).name == "NTUSER.DAT"]
    assert len(ntuser_rows) == 2
    assert {Path(r["output_path"]).parent.name for r in ntuser_rows} == {"alice", "bob"}

    # files actually written (long_path handles the >260-char output paths)
    for r in rows:
        st = os.stat(long_path(r["output_path"]))
        assert st.st_size == int(r["size_bytes"])

    runinfo = (run / "acquisition_collect_runinfo.json")
    assert runinfo.is_file()
    assert (run / "acquisition_collect_summary.txt").read_text().startswith("acquisition_collect")


def test_zip_collection_and_maxsize(tmp_path):
    src = tmp_path / "image_c"
    src.mkdir()
    _make_source(src)
    dest = tmp_path / "out"

    rc = main([
        "-d", str(dest), "--source", str(src), "--os", "windows",
        "--target-dir", str(_targets_dir(tmp_path)),
        "--container", "zip", "--max-size", "300",
    ])
    assert rc == 0
    run = next(dest.glob("acquisition_collect_*"))
    zpath = run / "collection.zip"
    assert zpath.is_file()
    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
    # System.evtx (1000 bytes) and the 500-byte hives exceed 300 and are skipped
    assert all("System.evtx" not in n for n in names)
    assert any("CALC.EXE-1234.pf" in n for n in names)

    errs = list(csv.DictReader((run / "acquisition_collect_errors.csv").open(encoding="utf-8-sig")))
    assert any(e["stage"] == "size" for e in errs)


def test_list_targets_runs(capsys):
    rc = main(["--list-targets", "--all-os"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "windows" in out and "linux" in out and "macos" in out


def test_dry_run_writes_nothing(tmp_path):
    src = tmp_path / "image_c"
    src.mkdir()
    _make_source(src)
    dest = tmp_path / "out"
    rc = main([
        "-d", str(dest), "--source", str(src), "--os", "windows",
        "--target-dir", str(_targets_dir(tmp_path)), "--dry-run",
    ])
    assert rc == 0
    run = next(dest.glob("acquisition_collect_*"))
    assert not (run / "collection").exists() or not any((run / "collection").rglob("*"))
