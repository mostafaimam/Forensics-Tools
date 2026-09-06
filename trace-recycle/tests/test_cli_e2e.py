import csv
import json
from datetime import datetime, timezone

from _helpers import make_i_v2, make_info2, make_info2_record
from trace_recycle.cli import main
from trace_recycle.scanner import scan


def _build_bin(root):
    """A realistic Vista+ $Recycle.Bin/<SID> layout."""
    sid = "S-1-5-21-1004336348-1177238915-682003330-1013"
    d = root / "$Recycle.Bin" / sid
    d.mkdir(parents=True)
    dt = datetime(2023, 2, 14, 9, 0, 0, tzinfo=timezone.utc)
    (d / "$I7GH2K3.docx").write_bytes(
        make_i_v2(r"C:\Users\alice\Desktop\plan.docx", 20000, dt))
    (d / "$R7GH2K3.docx").write_bytes(b"DOCXDATA")
    (d / "$IZZZ999.zip").write_bytes(
        make_i_v2(r"C:\Users\alice\Downloads\archive.zip", 999, dt))
    # note: no $R for the zip
    (d / "$RORPHAN.tmp").write_bytes(b"orphan content")
    return d, sid


def test_scan_recycle_bin(tmp_path):
    d, sid = _build_bin(tmp_path)
    res = scan([str(tmp_path)])
    real = [r for r in res.records if not r.parse_error]
    paths = {r.original_path for r in real}
    assert r"C:\Users\alice\Desktop\plan.docx" in paths
    assert r"C:\Users\alice\Downloads\archive.zip" in paths

    plan = next(r for r in real if r.original_path.endswith("plan.docx"))
    assert plan.sid == sid
    assert plan.content_present is True
    assert plan.content_path.endswith("$R7GH2K3.docx")

    zip_rec = next(r for r in real if r.original_path.endswith("archive.zip"))
    assert zip_rec.content_present is False

    assert res.orphan_content == 1
    orphan = next(r for r in res.records
                  if r.source_kind == "$R" and "ORPHAN" in r.source)
    assert orphan.warnings


def test_cli_csv_and_json(tmp_path, capsys):
    _build_bin(tmp_path)
    out_csv = tmp_path / "out.csv"
    out_json = tmp_path / "out.json"
    rc = main([str(tmp_path), "--csv", str(out_csv), "--json", str(out_json), "-q"])
    assert rc == 0

    rows = list(csv.DictReader(out_csv.open(encoding="utf-8-sig")))
    assert any(row["original_path"].endswith("plan.docx") for row in rows)
    assert any(row["content_present"] == "yes" for row in rows)

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data
    assert all("deleted_utc" in obj for obj in data)


def test_cli_single_info2_file(tmp_path, capsys):
    dt = datetime(2004, 8, 1, tzinfo=timezone.utc)
    f = tmp_path / "INFO2"
    f.write_bytes(make_info2([
        make_info2_record(r"C:\WINDOWS\Temp\junk.log", 0, 2, 512, dt),
    ]))
    rc = main([str(f)])
    assert rc == 0
    err = capsys.readouterr().err
    assert "1 deleted item" in err


def test_cli_missing_path(tmp_path):
    rc = main([str(tmp_path / "nope")])
    assert rc == 1


def test_csv_injection_neutralised(tmp_path):
    dt = datetime(2023, 1, 1, tzinfo=timezone.utc)
    d = tmp_path / "$Recycle.Bin" / "S-1-5-21-1-2-3-4"
    d.mkdir(parents=True)
    (d / "$IEVIL01.xlsx").write_bytes(
        make_i_v2(r"=cmd|'/c calc'!A1", 1, dt))
    out = tmp_path / "x.csv"
    main([str(tmp_path), "--csv", str(out), "-q"])
    raw = out.read_text(encoding="utf-8-sig")
    assert "'=cmd" in raw  # apostrophe-prefixed
