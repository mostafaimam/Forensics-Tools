from __future__ import annotations

import io
import json
import zipfile

import pytest

from utilities_ezview.extract import render
from utilities_ezview.cli import main


def _docx(tmp_path):
    p = tmp_path / "d.docx"
    doc = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas'
           '.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
           '<w:p><w:r><w:t>Hello </w:t></w:r><w:r><w:t>world</w:t></w:r>'
           '</w:p><w:p><w:r><w:t>Second paragraph.</w:t></w:r></w:p>'
           '</w:body></w:document>')
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", doc)
    return p


def _xlsx(tmp_path):
    p = tmp_path / "s.xlsx"
    ss = ('<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/'
          '2006/main"><si><t>name</t></si><si><t>Alice</t></si></sst>')
    sheet = ('<worksheet xmlns="http://schemas.openxmlformats.org/'
             'spreadsheetml/2006/main"><sheetData>'
             '<row r="1"><c r="A1" t="s"><v>0</v></c>'
             '<c r="B1"><v>42</v></c></row>'
             '<row r="2"><c r="A2" t="s"><v>1</v></c>'
             '<c r="B2"><v>7</v></c></row></sheetData></worksheet>')
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("xl/sharedStrings.xml", ss)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
    return p


def test_text_and_encoding(tmp_path):
    p = tmp_path / "log.txt"
    p.write_bytes("line one\nline two\n".encode("utf-16-le"))
    v = render(str(p))
    assert v.fmt == "text"
    assert v.encoding == "utf-16-le"
    assert "line two" in v.text


def test_csv(tmp_path):
    p = tmp_path / "data.csv"
    p.write_text("a,b,c\n1,2,3\n4,5,6\n")
    v = render(str(p))
    assert v.fmt == "csv"
    assert v.rows[0] == ["a", "b", "c"]
    assert len(v.rows) == 3


def test_html(tmp_path):
    p = tmp_path / "page.html"
    p.write_text("<html><head><style>x{}</style></head><body>"
                 "<h1>Title</h1><p>Some &amp; text</p>"
                 "<script>evil()</script></body></html>")
    v = render(str(p))
    assert v.fmt == "html"
    assert "Title" in v.text and "Some & text" in v.text
    assert "evil()" not in v.text


def test_rtf(tmp_path):
    p = tmp_path / "n.rtf"
    p.write_bytes(rb"{\rtf1\ansi {\fonttbl\f0 Arial;}\f0 Hello\par "
                  rb"World\'21\par}")
    v = render(str(p))
    assert v.fmt == "rtf"
    assert "Hello" in v.text and "World!" in v.text


def test_docx(tmp_path):
    v = render(str(_docx(tmp_path)))
    assert v.fmt == "docx"
    assert "Hello world" in v.text
    assert "Second paragraph." in v.text


def test_xlsx(tmp_path):
    v = render(str(_xlsx(tmp_path)))
    assert v.fmt == "xlsx"
    assert v.rows[0][0] == "name"
    assert v.rows[1][0] == "Alice"


def test_binary_fallback(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(bytes(range(256)) * 4 + b"readable string in here")
    v = render(str(p))
    assert v.fmt in ("binary", "text")
    assert "readable string in here" in v.text


def test_cli(tmp_path):
    d = _docx(tmp_path)
    (tmp_path / "x.csv").write_text("h1,h2\nv1,v2\n")
    js = tmp_path / "o.json"
    rc = main([str(d), str(tmp_path / "x.csv"), "--json", str(js), "-q"])
    assert rc == 0
    rows = json.loads(js.read_text())
    assert {r["format"] for r in rows} == {"docx", "csv"}

    tout = tmp_path / "out.txt"
    main([str(d), "--text-out", str(tout), "-q"])
    assert "Second paragraph." in tout.read_text()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
