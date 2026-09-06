import csv
import json

from analysis_index.cli import main, search_main


def _corpus(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("the malware beacon connects to 203.0.113.9 every hour")
    (src / "b.txt").write_text("routine backup log, nothing to see")
    (src / "c.md").write_text("incident notes: malware found on host WEB01")
    return src


def test_build_search_stats(tmp_path, capsys):
    src = _corpus(tmp_path)
    idx = tmp_path / "idx"
    assert main(["build", str(idx), str(src)]) == 0
    assert main(["stats", str(idx)]) == 0
    assert "documents     : 3" in capsys.readouterr().out

    rc = main(["search", str(idx), "malware"])
    out = capsys.readouterr().out
    assert rc == 0 and "a.txt" in out and "c.md" in out and "b.txt" not in out


def test_search_csv_and_exit_code(tmp_path):
    src = _corpus(tmp_path)
    idx = tmp_path / "idx"
    main(["build", str(idx), str(src), "-q"])
    out = tmp_path / "hits.csv"
    rc = main(["search", str(idx), '"malware beacon"', "--csv", str(out)])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 1 and rows[0]["path"].endswith("a.txt")
    assert int(rows[0]["matches"]) >= 1

    assert main(["search", str(idx), "nonexistentterm"]) == 1


def test_search_json_regex(tmp_path):
    src = _corpus(tmp_path)
    idx = tmp_path / "idx"
    main(["build", str(idx), str(src), "-q"])
    out = tmp_path / "r.json"
    main(["search", str(idx), r"/\d+\.\d+\.\d+\.\d+/", "--json", str(out)])
    data = json.loads(out.read_text())
    assert len(data) == 1 and data[0]["path"].endswith("a.txt")


def test_search_alias_prepends_subcommand(tmp_path, capsys):
    src = _corpus(tmp_path)
    idx = tmp_path / "idx"
    main(["build", str(idx), str(src), "-q"])
    rc = search_main([str(idx), "backup"])
    assert rc == 0 and "b.txt" in capsys.readouterr().out


def test_missing_index(tmp_path):
    assert main(["search", str(tmp_path / "nope"), "x"]) == 2


def test_list(tmp_path, capsys):
    src = _corpus(tmp_path)
    idx = tmp_path / "idx"
    main(["build", str(idx), str(src), "-q"])
    assert main(["list", str(idx)]) == 0
    assert "a.txt" in capsys.readouterr().out
