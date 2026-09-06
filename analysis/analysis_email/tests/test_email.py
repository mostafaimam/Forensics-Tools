import csv
import json

from _synth import eml, mbox, msg
from analysis_email.cli import main
from analysis_email.formats import parse_file


def test_eml_basic(tmp_path):
    p = tmp_path / "m.eml"
    p.write_bytes(eml(subject="Q3 numbers", body="see attached",
                      attachments=[("q3.xlsx", b"PK\x03\x04fakexlsx",
                                    "application/vnd.ms-excel")]))
    (m,) = parse_file(str(p))
    assert m.container == "eml"
    assert m.subject == "Q3 numbers"
    assert m.from_addr == "alice@good.example"
    assert m.date == "2026-09-01T08:00:00Z"
    assert len(m.attachments) == 1
    assert m.attachments[0].name == "q3.xlsx"
    assert m.attachments[0].sha256
    assert any("203.0.113.5" == r["ip"] for r in m.received_chain)


def test_eml_spoof_flag(tmp_path):
    p = tmp_path / "s.eml"
    p.write_bytes(eml(frm="Boss <boss@company.example>",
                      return_path="evil@attacker.example",
                      extra_headers=[("Reply-To", "evil@attacker.example")]))
    (m,) = parse_file(str(p))
    assert any("Return-Path" in f for f in m.flags)


def test_mbox_multiple(tmp_path):
    p = tmp_path / "inbox.mbox"
    p.write_bytes(mbox([
        eml(subject="one", frm="a@x.example"),
        eml(subject="two", frm="b@x.example"),
        eml(subject="three", frm="c@x.example"),
    ]))
    msgs = parse_file(str(p))
    assert len(msgs) == 3
    assert [m.subject for m in msgs] == ["one", "two", "three"]
    assert msgs[1].index == 1


def test_msg_outlook(tmp_path):
    p = tmp_path / "wire.msg"
    p.write_bytes(msg(attachments=[("instructions.pdf", b"%PDF-1.4 fake")]))
    (m,) = parse_file(str(p))
    assert m.container == "msg"
    assert m.subject == "Wire transfer request"
    assert m.from_addr == "ceo@company.example"
    assert m.to == "cfo@company.example"
    assert m.date == "2026-09-01T09:30:00Z"
    assert m.delivered == "2026-09-01T09:31:00Z"
    assert m.x_originating_ip == "198.51.100.9"
    assert m.attachments and m.attachments[0].name == "instructions.pdf"
    assert any("Return-Path" in f for f in m.flags)      # ceo@company vs @attacker


def test_cli_csv_and_flagged(tmp_path):
    d = tmp_path / "mail"
    d.mkdir()
    (d / "ok.eml").write_bytes(eml(subject="normal"))
    (d / "bad.msg").write_bytes(msg())
    out = tmp_path / "m.csv"
    rc = main(["scan", str(d), "--csv", str(out), "-q"])
    assert rc == 1                                       # a flagged message
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    subs = {r["subject"] for r in rows}
    assert "normal" in subs and "Wire transfer request" in subs

    out2 = tmp_path / "f.json"
    main(["scan", str(d), "--flagged-only", "--json", str(out2), "-q"])
    data = json.loads(out2.read_text())
    assert all(r["flags"] for r in data)


def test_cli_attachments_dir(tmp_path):
    p = tmp_path / "a.eml"
    p.write_bytes(eml(attachments=[("secret.txt", b"top secret", "text/plain")]))
    adir = tmp_path / "att"
    main(["scan", str(p), "--attachments-dir", str(adir), "-q"])
    saved = list(adir.rglob("*"))
    files = [f for f in saved if f.is_file()]
    assert files and files[0].read_bytes() == b"top secret"


def test_pst_reports_not_implemented(tmp_path, capsys):
    p = tmp_path / "mail.pst"
    p.write_bytes(b"!BDN" + b"\x00" * 512)
    rc = main(["scan", str(p), "-q"])
    assert "PST" in capsys.readouterr().err


def test_missing(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2
