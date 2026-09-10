from __future__ import annotations

import json

import pytest

import _synth as S

from utilities_ole.analyze import analyze
from utilities_ole.vba import decompress
from utilities_ole.cli import main


def test_ole2_doc(tmp_path):
    p = tmp_path / "report.doc"
    p.write_bytes(S.build_doc())
    rep = analyze(str(p))
    assert rep.container == "ole2"
    assert rep.properties["author"] == "Alice"
    assert rep.properties["last_saved_by"] == "Bob"
    assert rep.properties["created"] == "2026-03-10T09:00:00Z"
    assert rep.properties["company"] == "Acme Corp"
    assert rep.macros
    name, lines, susp = rep.macro_modules[0]
    assert name == "Module1"
    assert "AutoOpen" in susp and "WScript.Shell" in susp
    assert rep.severity == "high"
    assert "macro uses auto-exec / shell / download constructs" in rep.notable


def test_vba_decompress_roundtrip():
    src = b"Attribute VB_Name = \"M\"\r\nSub X()\r\nEnd Sub\r\n"
    import struct
    container = b"\x01" + struct.pack("<H", 0x0FFF) + src.ljust(4096, b"\x00")
    assert decompress(container).rstrip(b"\x00") == src


def test_ooxml_docx(tmp_path):
    p = tmp_path / "q.docx"
    p.write_bytes(S.build_docx(remote_template="http://evil.example/t.dotm"))
    rep = analyze(str(p))
    assert rep.container == "ooxml"
    assert rep.doc_kind == "docx"
    assert rep.properties["title"] == "Quarterly Report"
    assert rep.properties["author"] == "Alice"
    assert "http://evil.example/t.dotm" in rep.external_targets
    assert any("external relationship target" in n for n in rep.notable)


def test_ooxml_macro_enabled(tmp_path):
    p = tmp_path / "x.docm"
    p.write_bytes(S.build_docx(macro=True))
    rep = analyze(str(p))
    assert rep.macros
    assert rep.macro_modules and rep.macro_modules[0][2]
    assert rep.severity == "high"


def test_cli_csv_json(tmp_path):
    (tmp_path / "a.doc").write_bytes(S.build_doc())
    (tmp_path / "b.docx").write_bytes(S.build_docx())
    csv_p = tmp_path / "o.csv"
    js_p = tmp_path / "o.json"
    rc = main([str(tmp_path / "a.doc"), str(tmp_path / "b.docx"),
               "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert any(r["kind"] == "property" and r["name"] == "author"
               for r in rows)
    assert any(r["kind"] == "macro-module" for r in rows)

    main([str(tmp_path / "a.doc"), "--min-severity", "high",
          "--json", str(js_p), "-q"])
    hi = json.loads(js_p.read_text())
    assert hi and all(r["severity"] == "high" for r in hi)


def test_not_a_compound_file(tmp_path):
    p = tmp_path / "plain.txt"
    p.write_bytes(b"just some text, not OLE or a zip")
    rep = analyze(str(p))
    assert rep.container in ("unknown",)
    assert rep.error


def test_csv_injection_guard():
    from utilities_ole.tracelib import sanitize
    assert sanitize("=1+2") == "'=1+2"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
