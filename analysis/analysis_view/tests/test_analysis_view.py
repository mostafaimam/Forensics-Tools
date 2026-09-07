import csv
import json

import pytest

from analysis_view.cli import main
from analysis_view.filters import apply_filters, apply_search, apply_sort, parse
from analysis_view.htmlview import build_html
from analysis_view.model import Review, Table, row_id
from analysis_view.output import export_csv
from analysis_view.reader import load

import _synth as s

_HDR = ["time", "host", "severity", "msg"]
_ROWS = [
    ["2026-08-14T20:10:00", "WKS01", "high", "powershell -enc AAAA"],
    ["2026-08-14T20:11:00", "WKS01", "low", "logon type 10"],
    ["2026-08-14T20:30:00", "SRV02", "medium", "service install: UpdateSvc"],
    ["2026-08-14T21:00:00", "SRV02", "high", "beacon to 185.43.99.42"],
]


def _csv(tmp_path, name="a.csv", delim=","):
    p = tmp_path / name
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, delimiter=delim)
        w.writerow(_HDR)
        w.writerows(_ROWS)
    return p


def _jsonl(tmp_path, name="b.jsonl"):
    p = tmp_path / name
    p.write_text(json.dumps({"time": "2026-08-15T09:00:00", "host": "WKS01",
                             "severity": "medium", "msg": "usb inserted",
                             "extra": {"vid": "0951"}}) + "\n",
                 encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# readers
# --------------------------------------------------------------------------

def test_read_csv_tsv(tmp_path):
    rows, cols = load(str(_csv(tmp_path)))
    assert cols == _HDR and len(rows) == 4
    rows2, _ = load(str(_csv(tmp_path, "t.tsv", "\t")))
    assert len(rows2) == 4 and rows2[0]["host"] == "WKS01"


def test_read_json_flattens(tmp_path):
    rows, cols = load(str(_jsonl(tmp_path)))
    assert "extra" in cols
    assert "0951" in rows[0]["extra"]


def test_read_xlsx(tmp_path):
    p = tmp_path / "book.xlsx"
    s.write_xlsx(str(p), _HDR, _ROWS)
    rows, cols = load(str(p))
    assert cols == _HDR
    assert len(rows) == 4
    assert rows[3]["msg"].startswith("beacon")


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------

def test_table_merge_and_ids(tmp_path):
    t = Table.from_paths([str(_csv(tmp_path)), str(_jsonl(tmp_path))])
    assert len(t.rows) == 5
    assert t.sources == ["a.csv", "b.jsonl"]
    assert "_source" in t.display_columns()
    assert len({r["_id"] for r in t.rows}) == 5     # stable unique ids
    # missing column filled
    assert all("extra" in r for r in t.rows)


def test_review_roundtrip(tmp_path):
    rv = Review()
    rv.tags["abc"] = ["lateral-movement"]
    rv.notes["abc"] = "confirmed"
    rv.reviewed.add("def")
    f = tmp_path / "r.json"
    rv.save(f)
    back = Review.from_file(f)
    assert back.tags == {"abc": ["lateral-movement"]}
    assert back.notes["abc"] == "confirmed"
    assert "def" in back.reviewed


# --------------------------------------------------------------------------
# filters
# --------------------------------------------------------------------------

def test_filter_ops(tmp_path):
    t = Table.from_paths([str(_csv(tmp_path))])
    assert len(apply_filters(t.rows, ["severity=high"])) == 2
    assert len(apply_filters(t.rows, ["msg~powershell"])) == 1
    assert len(apply_filters(t.rows, ["host!=WKS01"])) == 2
    assert len(apply_filters(t.rows, ["severity=high", "host=SRV02"])) == 1
    assert len(apply_filters(t.rows, ["severity=high", "severity=low"],
                             "or")) == 3
    assert len(apply_filters(t.rows, ["185.43"])) == 1      # bare -> full text


def test_search_and_sort(tmp_path):
    t = Table.from_paths([str(_csv(tmp_path))])
    assert len(apply_search(t.rows, "SRV02")) == 2
    s_desc = apply_sort(t.rows, "time:desc")
    assert s_desc[0]["time"] == "2026-08-14T21:00:00"
    s_sev = apply_sort(t.rows, "severity")
    assert [r["severity"] for r in s_sev][0] == "high"


def test_parse_star_column(tmp_path):
    pred = parse("* ~ beacon")
    t = Table.from_paths([str(_csv(tmp_path))])
    assert sum(1 for r in t.rows if pred(r)) == 1


# --------------------------------------------------------------------------
# html + export
# --------------------------------------------------------------------------

def test_build_html_embeds_data(tmp_path):
    t = Table.from_paths([str(_csv(tmp_path))])
    rv = Review()
    rv.tags[t.rows[0]["_id"]] = ["c2"]
    h = build_html(t, rv, rules=[{"col": "severity", "match": "high",
                                  "color": "#fdd"}])
    assert "powershell -enc AAAA" in h
    assert '"c2"' in h
    assert "colour rules" in h
    assert h.count("<script>") == 1


def test_export_csv_with_review(tmp_path):
    t = Table.from_paths([str(_csv(tmp_path))])
    rv = Review()
    rid = t.rows[0]["_id"]
    rv.tags[rid] = ["c2", "persistence"]
    rv.notes[rid] = "malicious"
    rv.reviewed.add(rid)
    out = tmp_path / "e.csv"
    export_csv(t.rows, t.display_columns(), out, rv)
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    r0 = rows[0]
    assert r0["tags"] == "c2|persistence"
    assert r0["note"] == "malicious" and r0["reviewed"] == "yes"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_html_and_export(tmp_path):
    c = _csv(tmp_path)
    j = _jsonl(tmp_path)
    hp = tmp_path / "review.html"
    ep = tmp_path / "hi.csv"
    rc = main([str(c), str(j), "--html", str(hp),
               "--filter", "severity=high", "--export", str(ep), "-q"])
    assert rc == 0
    assert hp.read_text(encoding="utf-8").count("beacon") >= 1
    rows = list(csv.DictReader(ep.open(encoding="utf-8-sig")))
    assert len(rows) == 2 and all(r["severity"] == "high" for r in rows)


def test_cli_sort_and_rule(tmp_path):
    c = _csv(tmp_path)
    hp = tmp_path / "r.html"
    main([str(c), "--sort", "time:desc", "--rule", "msg~beacon=#f88",
          "--html", str(hp), "-q"])
    text = hp.read_text(encoding="utf-8")
    assert '"match": "beacon"' in text


def test_cli_review_export(tmp_path):
    c = _csv(tmp_path)
    rv = Review()
    t = Table.from_paths([str(c)])
    rv.reviewed.add(t.rows[1]["_id"])
    rp = tmp_path / "rev.json"
    rv.save(rp)
    ep = tmp_path / "out.csv"
    main([str(c), "--review", str(rp), "--export", str(ep), "-q"])
    rows = list(csv.DictReader(ep.open(encoding="utf-8-sig")))
    assert sum(1 for r in rows if r["reviewed"] == "yes") == 1


def test_cli_no_path():
    with pytest.raises(SystemExit):
        main([])


def test_cli_csv_injection_guard(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("name,val\n=cmd|calc,ok\n", encoding="utf-8")
    out = tmp_path / "o.csv"
    main([str(p), "--export", str(out), "-q"])
    assert "'=cmd|calc" in out.read_text(encoding="utf-8-sig")
