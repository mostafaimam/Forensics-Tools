import zipfile

from analysis_index.extract import extract


def test_plain_text(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("error: disk full at /var/log")
    text, kind = extract(p, max_size=1 << 20)
    assert kind == "text" and "disk full" in text


def test_markup_strips_tags_keeps_urls(tmp_path):
    p = tmp_path / "a.html"
    p.write_text('<p>hello <b>world</b></p>'
                 '<a href="https://bad.example/x">click</a>')
    text, kind = extract(p, max_size=1 << 20)
    assert kind == "markup"
    assert "hello world click" in " ".join(text.split())
    assert "https://bad.example/x" in text


def test_ooxml_docx(tmp_path):
    p = tmp_path / "memo.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml",
                   "<w:document><w:p><w:t>Confidential merger plan</w:t>"
                   "</w:p></w:document>")
    text, kind = extract(p, max_size=1 << 20)
    assert kind == "ooxml" and "Confidential merger plan" in text


def test_email(tmp_path):
    p = tmp_path / "m.eml"
    p.write_bytes(b"From: a@x.com\r\nTo: b@y.com\r\nSubject: Payment\r\n\r\n"
                  b"Please wire the funds today.\r\n")
    text, kind = extract(p, max_size=1 << 20)
    assert kind == "email"
    assert "Payment" in text and "wire the funds" in text and "a@x.com" in text


def test_binary_strings_fallback(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01\x02SECRET_KEY=abcdef\x00\xff\xfe"
                  + "wide string here".encode("utf-16-le"))
    text, kind = extract(p, max_size=1 << 20)
    assert kind == "strings"
    assert "SECRET_KEY=abcdef" in text and "wide string here" in text


def test_large_file_skipped(tmp_path):
    p = tmp_path / "big.txt"
    p.write_text("x" * 5000)
    text, kind = extract(p, max_size=1000)
    assert kind == "skipped-large" and text == ""
