import csv
import json
import os
from datetime import datetime, timezone

import pytest

from _synth import make_scca_v30, wrap_mam
from windows_prefetch.cli import main

RUNS = [datetime(2024, 5, 5, 5, 5, 5, tzinfo=timezone.utc)]
REFS = [r"\VOL\A.DLL", r"\VOL\B.DLL"]


def _write_pf(path, name, compressed=False):
    scca = make_scca_v30(name, RUNS, 11, REFS)
    path.write_bytes(wrap_mam(scca) if compressed else scca)


def test_dir_scan_csv_and_files_csv(tmp_path):
    d = tmp_path / "Prefetch"
    d.mkdir()
    _write_pf(d / "NOTEPAD.EXE-1.pf", "NOTEPAD.EXE")
    _write_pf(d / "CALC.EXE-2.pf", "CALC.EXE")

    out = tmp_path / "pf.csv"
    files = tmp_path / "refs.csv"
    rc = main([str(d), "--csv", str(out), "--files-csv", str(files), "-q"])
    assert rc == 0

    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert {r["executable"] for r in rows} == {"NOTEPAD.EXE", "CALC.EXE"}
    assert all(r["run_count"] == "11" for r in rows)
    assert all(r["run_time_1_utc"].endswith("Z") for r in rows)

    frows = list(csv.DictReader(files.open(encoding="utf-8-sig")))
    assert len(frows) == 4
    assert {r["referenced_file"] for r in frows} == set(REFS)


@pytest.mark.skipif(os.name != "nt", reason="MAM build needs ntdll")
def test_compressed_json(tmp_path, capsys):
    _write_pf(tmp_path / "EDGE.EXE-9.pf", "EDGE.EXE", compressed=True)
    out = tmp_path / "pf.json"
    rc = main([str(tmp_path / "EDGE.EXE-9.pf"), "--json", str(out), "-q"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data[0]["executable"] == "EDGE.EXE"
    assert data[0]["compressed"] is True
    assert data[0]["referenced_files"] == REFS


def test_bad_file_is_error_row(tmp_path, capsys):
    (tmp_path / "junk.pf").write_bytes(b"not a prefetch")
    rc = main([str(tmp_path / "junk.pf")])
    assert rc == 1
    assert "0 parsed, 1 error" in capsys.readouterr().err


def test_csv_injection(tmp_path):
    scca = make_scca_v30("=WEIRD.EXE", RUNS, 1, [r"=\VOL\EVIL.DLL"])
    (tmp_path / "x.pf").write_bytes(scca)
    out = tmp_path / "x.csv"
    main([str(tmp_path / "x.pf"), "--csv", str(out), "-q"])
    raw = out.read_text(encoding="utf-8-sig")
    assert "'=WEIRD.EXE" in raw
