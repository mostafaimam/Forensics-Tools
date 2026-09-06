import json

from analysis_report.cli import main
from analysis_report.ingest import load
from analysis_report.md import render as md
from analysis_report.render import build_html


def _csv(p, text):
    p.write_text(text, encoding="utf-8")
    return p


def test_ingest_detects_tool_and_alerts(tmp_path):
    f = _csv(tmp_path / "enc.csv",
             "path,size,verdict,scheme\n"
             "/a.tc,1048576,high-entropy,veracrypt-like\n"
             "/b.txt,10,clear,\n")
    src = load(str(f))
    assert src.tool == "analysis_encryption"
    assert src.row_count == 2 and src.alert_rows == 1
    assert src.sha256


def test_ingest_json(tmp_path):
    f = tmp_path / "ps.json"
    f.write_text(json.dumps([
        {"pid": 4, "ppid": 0, "name": "System", "create_time": "2026-09-01"},
        {"pid": 66, "ppid": 4, "name": "x.exe", "create_time": "2026-09-01"},
    ]))
    src = load(str(f))
    assert src.tool == "memory_pslist" and src.row_count == 2


def test_markdown():
    h = md("# Title\n\nSome **bold** and `code`.\n\n- one\n- two\n")
    assert "<h1>Title</h1>" in h
    assert "<strong>bold</strong>" in h and "<code>code</code>" in h
    assert "<ul><li>one</li><li>two</li></ul>" in h


def test_build_html(tmp_path):
    a = _csv(tmp_path / "timeline.csv",
             "timestamp_utc,tool,description\n"
             "2026-09-01T08:00:00Z,windows_evtx,logon 4624\n")
    b = _csv(tmp_path / "kff.csv",
             "path,status,set\n/mal.exe,known-bad,iocs\n/ok.dll,known-good,nsrl\n")
    src = [load(str(a)), load(str(b))]
    html = build_html(title="Case X", meta={"case_number": "2026-1"},
                      sources=src, notes_md="## Findings\nAttacker ran x.exe.")
    assert "Case X" in html and "2026-1" in html
    assert "windows_evtx" in html and "analysis_kff" in html
    assert 'class="alert"' in html          # the known-bad row
    assert "Attacker ran x.exe" in html
    assert src[1].sha256 in html            # manifest


def test_cli_end_to_end(tmp_path):
    _csv(tmp_path / "a.csv", "path,verdict,scheme\n/x.age,encrypted,age\n")
    note = tmp_path / "n.md"
    note.write_text("# Summary\nOne encrypted file found.")
    out = tmp_path / "report.html"
    bundle = tmp_path / "report.json"
    rc = main(["build", str(out), "--title", "IR-2026-014",
               "--input", str(tmp_path), "--note", str(note),
               "--case", "2026-014", "--examiner", "A. Analyst",
               "--json", str(bundle), "-q"])
    assert rc == 0
    h = out.read_text()
    assert "IR-2026-014" in h and "A. Analyst" in h and "encrypted" in h
    data = json.loads(bundle.read_text())
    assert data["summary"]["alert_rows"] == 1
    assert data["sources"][0]["tool"] == "analysis_encryption"


def test_cli_no_input(tmp_path):
    assert main(["build", str(tmp_path / "r.html")]) == 2
