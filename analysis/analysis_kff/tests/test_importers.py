from _synth import csv_list, h, lines_list, nsrl_sqlite, nsrl_text, projectvic
from analysis_kff.importers import detect_format, parse

R = [h(b"one"), h(b"two"), h(b"three")]


def test_detect_and_parse_nsrl_text(tmp_path):
    p = nsrl_text(tmp_path / "NSRLFile.txt", R)
    assert detect_format(p) == "nsrl-text"
    recs = list(parse(str(p)))
    assert len(recs) == 3
    assert recs[0]["md5"].lower() == R[0]["md5"]
    assert recs[0]["sha1"].lower() == R[0]["sha1"]


def test_parse_nsrl_sqlite(tmp_path):
    p = nsrl_sqlite(tmp_path / "RDS.db", R)
    assert detect_format(p) == "nsrl-sqlite"
    recs = list(parse(str(p)))
    got = {r["sha256"] for r in recs}
    assert got == {x["sha256"] for x in R}


def test_parse_projectvic(tmp_path):
    p = projectvic(tmp_path / "vic.json", R)
    assert detect_format(p) == "projectvic"
    recs = list(parse(str(p)))
    assert {r["md5"] for r in recs} == {x["md5"] for x in R}


def test_parse_csv(tmp_path):
    p = csv_list(tmp_path / "set.csv", R)
    recs = list(parse(str(p), "csv"))
    assert len(recs) == 3 and recs[1]["sha1"] == R[1]["sha1"]


def test_parse_lines_mixed(tmp_path):
    p = lines_list(tmp_path / "hashes.txt", R)
    recs = list(parse(str(p), "lines"))
    algos = {a for r in recs for a in r}
    assert "md5" in algos and "sha256" in algos
