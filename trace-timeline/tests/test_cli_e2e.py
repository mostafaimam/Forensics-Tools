import csv
import json

from trace_timeline.cli import main

PREFETCH_CSV = (
    "executable,run_count,last_run_utc,version,prefetch_hash,referenced_files,"
    "volume_count,run_time_1_utc,run_time_2_utc,run_time_3_utc,run_time_4_utc,"
    "run_time_5_utc,run_time_6_utc,run_time_7_utc,run_time_8_utc,volume_devices,"
    "volume_serials,volume_created_utc,compressed,decompressor,source,warnings,"
    "parse_error\r\n"
    "CHROME.EXE,5,2024-03-02T10:00:00.000000Z,30,ABCD,12,1,"
    "2024-03-02T10:00:00.000000Z,2024-03-01T09:00:00.000000Z,,,,,,,"
    "\\VOL,1A2B,2024-01-01T00:00:00.000000Z,yes,ntdll,CHROME.EXE-1.pf,,\r\n"
)

RECYCLE_CSV = (
    "original_path,original_size,deleted_utc,drive,sid,recycle_id,index,"
    "content_present,content_path,content_is_dir,active,source_kind,"
    "format_version,source,warnings,parse_error\r\n"
    "C:\\Users\\alice\\secret.docx,4096,2024-03-01T15:30:00.000000Z,C:,"
    "S-1-5-21-1-2-3-1001,AB12,,,no,,yes,$I,2,"
    "C:\\$Recycle.Bin\\S-1-5-21-1-2-3-1001\\$IAB12.docx,,\r\n"
)


def test_merge_prefetch_and_recycle(tmp_path, capsys):
    (tmp_path / "pf.csv").write_text(PREFETCH_CSV, encoding="utf-8")
    (tmp_path / "rb.csv").write_text(RECYCLE_CSV, encoding="utf-8")
    out = tmp_path / "tl.csv"

    rc = main([str(tmp_path), "--csv", str(out), "-q"])
    assert rc == 0

    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    # 2 prefetch run times + 1 volume-created + 1 recycle deleted = 4
    assert len(rows) == 4
    assert [r["timestamp_utc"] for r in rows] == sorted(r["timestamp_utc"] for r in rows)
    types = {r["timestamp_type"] for r in rows}
    assert types == {"execution", "volume-created", "deleted"}
    assert any("CHROME.EXE executed" in r["description"] for r in rows)
    assert any("secret.docx" in r["description"] for r in rows)


def test_time_and_grep_filters(tmp_path):
    (tmp_path / "pf.csv").write_text(PREFETCH_CSV, encoding="utf-8")
    (tmp_path / "rb.csv").write_text(RECYCLE_CSV, encoding="utf-8")
    out = tmp_path / "tl.csv"
    rc = main([str(tmp_path), "--csv", str(out), "-q",
               "--from", "2024-03-02", "--grep", "chrome"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 1
    assert rows[0]["timestamp_type"] == "execution"


def test_generic_csv_with_fields(tmp_path):
    (tmp_path / "app.csv").write_text(
        "ts,level,msg\n"
        "2024-03-01T00:00:01Z,INFO,started\n"
        "2024-03-01T00:00:05Z,WARN,disk slow\n",
        encoding="utf-8",
    )
    out = tmp_path / "tl.jsonl"
    rc = main([str(tmp_path / "app.csv"), "--time-field", "ts",
               "--message-field", "msg", "--jsonl", str(out), "-q"])
    assert rc == 0
    lines = [json.loads(x) for x in out.read_text().splitlines()]
    assert [x["description"] for x in lines] == ["started", "disk slow"]
    assert all(x["tool"] == "generic-csv" for x in lines)


def test_epoch_generic(tmp_path):
    (tmp_path / "e.csv").write_text("when,what\n1709296200,thing\n", encoding="utf-8")
    out = tmp_path / "o.csv"
    rc = main([str(tmp_path / "e.csv"), "--time-field", "when", "--epoch",
               "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows[0]["timestamp_utc"].startswith("2024-03-01T12:30:00")


def test_dedupe(tmp_path):
    (tmp_path / "a.csv").write_text(PREFETCH_CSV, encoding="utf-8")
    (tmp_path / "b.csv").write_text(PREFETCH_CSV, encoding="utf-8")
    out = tmp_path / "o.csv"
    main([str(tmp_path), "--csv", str(out), "-q", "--dedupe"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 3  # not 6


def test_html_viewer(tmp_path):
    (tmp_path / "pf.csv").write_text(PREFETCH_CSV, encoding="utf-8")
    out = tmp_path / "tl.html"
    rc = main([str(tmp_path / "pf.csv"), "--html", str(out), "-q"])
    assert rc == 0
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    assert "CHROME.EXE executed" in page
    assert "const DATA = [" in page
    assert "__DATA__" not in page and "__TITLE__" not in page


def test_prefetch_json_input(tmp_path):
    obj = [{
        "source": "CHROME.EXE-1.pf", "executable": "CHROME.EXE",
        "run_times_utc": ["2024-03-02T10:00:00.000000Z",
                          "2024-03-01T09:00:00.000000Z"],
        "referenced_files": ["a", "b", "c"],
    }]
    (tmp_path / "pf.json").write_text(json.dumps(obj), encoding="utf-8")
    out = tmp_path / "o.csv"
    rc = main([str(tmp_path / "pf.json"), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 2
    assert all("CHROME.EXE executed (3 files referenced)" in r["description"]
               for r in rows)
