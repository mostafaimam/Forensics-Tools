import csv
import json

from _synth import build_jumplist
from windows_jumplist.cli import main


def _write(tmp_path, app_id="12dc1ea8e34b5a6"):
    data, name = build_jumplist(app_id=app_id)
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_csv(tmp_path):
    p = _write(tmp_path)
    out = tmp_path / "jl.csv"
    rc = main([str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 2
    assert rows[0]["mru_position"] == "0"
    assert rows[0]["target_path"] == r"C:\Users\a\Desktop\latest.png"
    assert rows[0]["last_used_utc"].endswith("Z")
    assert "Photo" in rows[0]["application"]
    assert rows[0]["lnk_drive_serial"] == "AABBCCDD"


def test_pinned_only(tmp_path):
    p = _write(tmp_path)
    out = tmp_path / "p.json"
    main([str(p), "--pinned-only", "--json", str(out), "-q"])
    data = json.loads(out.read_text())
    assert len(data) == 1 and data[0]["pinned"] == "yes"


def test_directory_scan(tmp_path):
    _write(tmp_path, "12dc1ea8e34b5a6")
    _write(tmp_path, "5f7b5f1e01b83767")
    out = tmp_path / "all.csv"
    rc = main([str(tmp_path), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 4
    assert {"12dc1ea8e34b5a6", "5f7b5f1e01b83767"} == {r["app_id"] for r in rows}


def test_bad_file(tmp_path):
    (tmp_path / "x.automaticDestinations-ms").write_bytes(b"garbage")
    assert main([str(tmp_path / "x.automaticDestinations-ms"), "-q"]) == 1
