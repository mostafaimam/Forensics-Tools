import csv
import json

from _synth import h, nsrl_text
from analysis_kff.cli import main


def _db(tmp_path):
    return ["--db", str(tmp_path / "kff.db")]


def _seed(tmp_path):
    good = nsrl_text(tmp_path / "good.txt", [h(b"known-benign-1"), h(b"known-benign-2")])
    bad = tmp_path / "bad.txt"
    e = h(b"evil.exe")
    bad.write_text(f"{e['md5']}\n{e['sha1']}\n{e['sha256']}\n")
    assert main(_db(tmp_path) + ["import", str(good), "--name", "nsrl",
                                 "--category", "known-good"]) == 0
    assert main(_db(tmp_path) + ["import", str(bad), "--name", "iocs",
                                 "--category", "known-bad", "--format",
                                 "lines"]) == 0


def test_import_sets_and_stats(tmp_path, capsys):
    _seed(tmp_path)
    main(_db(tmp_path) + ["sets"])
    out = capsys.readouterr().out
    assert "nsrl" in out and "known-good" in out and "iocs" in out


def test_scan_classifies(tmp_path):
    _seed(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.dll").write_bytes(b"known-benign-1")
    (target / "b.exe").write_bytes(b"evil.exe")
    (target / "c.txt").write_bytes(b"brand new file")
    out = tmp_path / "r.csv"
    rc = main(_db(tmp_path) + ["scan", str(target), "--csv", str(out)])
    assert rc == 1            # an alert was found
    rows = {r["path"].split("\\")[-1].split("/")[-1]: r
            for r in csv.DictReader(out.open(encoding="utf-8-sig"))}
    assert rows["a.dll"]["status"] == "known-good"
    assert rows["b.exe"]["status"] == "known-bad" and rows["b.exe"]["set"] == "iocs"
    assert rows["c.txt"]["status"] == "unknown"


def test_scan_alerts_only(tmp_path):
    _seed(tmp_path)
    t = tmp_path / "t"
    t.mkdir()
    (t / "good").write_bytes(b"known-benign-2")
    (t / "bad").write_bytes(b"evil.exe")
    out = tmp_path / "a.json"
    main(_db(tmp_path) + ["scan", str(t), "--alerts-only", "--json", str(out)])
    data = json.loads(out.read_text())
    assert len(data) == 1 and data[0]["status"] == "known-bad"


def test_lookup(tmp_path, capsys):
    _seed(tmp_path)
    rc = main(_db(tmp_path) + ["lookup", h(b"evil.exe")["md5"],
                               h(b"unseen")["md5"]])
    out = capsys.readouterr().out
    assert "KNOWN-BAD" in out and "unknown" in out
    assert rc == 1


def test_scan_hash_list(tmp_path):
    _seed(tmp_path)
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"files": [
        {"path": "x/evil.exe", "md5": h(b"evil.exe")["md5"]},
        {"path": "x/clean", "md5": h(b"totally clean")["md5"]},
    ]}))
    out = tmp_path / "hl.csv"
    main(_db(tmp_path) + ["scan", "--hash-list", str(manifest), ".",
                          "--csv", str(out)])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    st = {r["path"]: r["status"] for r in rows}
    assert st["x/evil.exe"] == "known-bad" and st["x/clean"] == "unknown"


def test_scan_empty_index(tmp_path):
    assert main(_db(tmp_path) + ["scan", str(tmp_path)]) == 2
