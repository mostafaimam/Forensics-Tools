import csv
from datetime import datetime

from _synth import eprocess, lime_with
from memory_pslist.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d


def _dump(tmp_path):
    p = tmp_path / "mem.lime"
    p.write_bytes(lime_with([
        eprocess("lsass.exe", 764, 596, datetime(2026, 9, 1, 8, 0, 0)),
        eprocess("mal.exe", 6666, 764, datetime(2026, 9, 1, 9, 0, 0),
                 datetime(2026, 9, 1, 9, 1, 0)),
    ]))
    return p


def test_csv_output(tmp_path):
    out = tmp_path / "ps.csv"
    rc = main([str(_dump(tmp_path)), "--csv", str(out), "-q"])
    assert rc == 0
    rows = {r["name"]: r for r in csv.DictReader(out.open(encoding="utf-8-sig"))}
    assert rows["lsass.exe"]["pid"] == "764"
    assert rows["mal.exe"]["exited"] == "yes"


def test_terminated_only(tmp_path, capsys):
    rc = main([str(_dump(tmp_path)), "--terminated-only"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mal.exe" in out and "lsass.exe" not in out


def test_name_filter(tmp_path, capsys):
    main([str(_dump(tmp_path)), "--name", "lsass"])
    assert "lsass.exe" in capsys.readouterr().out


def test_missing(tmp_path):
    assert main([str(tmp_path / "nope")]) == 2
