import csv
import hashlib
import json

from analysis_dedupe.cli import main
from analysis_dedupe.scan import scan


def _tree(tmp_path):
    d = tmp_path / "data"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_bytes(b"hello world")
    (d / "b.txt").write_bytes(b"hello world")          # dup of a
    (d / "sub" / "c.txt").write_bytes(b"hello world")   # dup of a
    (d / "unique.bin").write_bytes(b"one of a kind content here")
    (d / "empty1").write_bytes(b"")
    (d / "empty2").write_bytes(b"")                     # same size, empty
    return d


def test_scan_groups_and_reclaimable(tmp_path):
    d = _tree(tmp_path)
    res = scan([str(d)], min_size=1)
    assert res.scanned == 4                # empties skipped (min_size=1)
    grp = res.groups[hashlib.sha256(b"hello world").hexdigest()]
    assert len(grp) == 3
    assert sum(1 for r in grp if r.representative) == 1
    assert res.reclaimable == len(b"hello world") * 2
    assert res.unique == 2


def test_size_prefilter_skips_lonely_files(tmp_path):
    d = _tree(tmp_path)
    res = scan([str(d)], min_size=1)
    uniq = next(r for r in res.files if r.path.endswith("unique.bin"))
    assert uniq.digest == ""              # never hashed - no size collision


def test_full_hashes_everything(tmp_path):
    d = _tree(tmp_path)
    res = scan([str(d)], full=True, min_size=1)
    assert all(r.digest for r in res.files)


def test_against_baseline(tmp_path):
    d = _tree(tmp_path)
    seen = {hashlib.sha256(b"hello world").hexdigest()}
    res = scan([str(d)], baseline=seen, full=True)
    statuses = {r.status for r in res.files}
    assert "baseline-hit" in statuses and "new" in statuses


def test_cli_csv_and_distinct(tmp_path):
    d = _tree(tmp_path)
    out = tmp_path / "f.csv"
    distinct = tmp_path / "u.txt"
    rc = main(["scan", str(d), "--csv", str(out), "--distinct-out",
               str(distinct), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    reps = [r for r in rows if r["representative"] == "yes" and r["digest"]]
    assert len(reps) == 1
    lines = distinct.read_text().split()
    assert any(x.endswith("a.txt") for x in lines)
    assert any(x.endswith("unique.bin") for x in lines)


def test_cli_against_new_only(tmp_path):
    d = _tree(tmp_path)
    base = tmp_path / "b.json"
    base.write_text(json.dumps({"files": [
        {"sha256": hashlib.sha256(b"hello world").hexdigest()}]}))
    out = tmp_path / "new.csv"
    main(["scan", str(d), "--against", str(base), "--new-only", "--full",
          "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["status"] == "new" for r in rows)
    assert not any("a.txt" in r["path"] for r in rows)


def test_missing(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2
