from __future__ import annotations

import hashlib
import json

import pytest

from network_http import output
from network_http.carve import analyze, extract
from network_http.cli import main

import _synth as S


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 400 + b"IEND\xaeB`\x82"
MZ = b"MZ\x90\x00" + b"\x03\x00" * 300 + b"This program cannot be run in DOS mode"
HTML = b"<!DOCTYPE html><html><body>" + b"hello world " * 500 + b"</body></html>"


def _write(tmp_path, packets, name="c.pcap", ng=False):
    p = tmp_path / name
    p.write_bytes(S.pcapng(packets) if ng else S.pcap(packets))
    return p


def test_reassembly_and_download(tmp_path):
    req = S.request("GET", "/img/logo.png", "example.com")
    resp = S.response(PNG, ctype="image/png")
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    assert len(res.objects) == 1
    o = res.objects[0]
    assert o.direction == "download"
    assert o.size == len(PNG)
    assert o.sha256 == hashlib.sha256(PNG).hexdigest()
    assert o.detected_type == "image/png"
    assert o.filename == "logo.png"
    assert o.method == "GET"
    assert o.status == 200


def test_out_of_order_segments(tmp_path):
    req = S.request("GET", "/big.bin", "example.com")
    body = bytes((i * 7) & 0xFF for i in range(9000))
    resp = S.response(body, ctype="application/octet-stream")
    cap = _write(tmp_path, S.convo(req, resp, mss=512,
                                   server_out_of_order=True))
    res = analyze([str(cap)])
    assert len(res.objects) == 1
    assert res.objects[0].sha256 == hashlib.sha256(body).hexdigest()


def test_chunked_decode(tmp_path):
    req = S.request("GET", "/stream", "example.com")
    resp = S.response(HTML, ctype="text/html", chunked=True)
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    assert len(res.objects) == 1
    assert res.objects[0].size == len(HTML)
    assert res.objects[0].sha256 == hashlib.sha256(HTML).hexdigest()


def test_gzip_decode(tmp_path):
    req = S.request("GET", "/page", "example.com")
    resp = S.response(HTML, ctype="text/html", encoding="gzip")
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    o = res.objects[0]
    assert o.encoding == "gzip"
    assert o.size == len(HTML)
    assert o.sha256 == hashlib.sha256(HTML).hexdigest()


def test_gzip_chunked_combo(tmp_path):
    req = S.request("GET", "/page", "example.com")
    resp = S.response(HTML, ctype="text/html", encoding="gzip", chunked=True)
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    assert res.objects[0].sha256 == hashlib.sha256(HTML).hexdigest()


def test_executable_body_flag(tmp_path):
    req = S.request("GET", "/update.exe", "cdn.example.com")
    resp = S.response(MZ, ctype="application/octet-stream")
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    n = res.objects[0].notable
    assert "PE executable body" in n
    assert output.row(res.objects[0])["severity"] == "high"


def test_content_type_mismatch_flag(tmp_path):
    req = S.request("GET", "/legit/page", "example.com")
    resp = S.response(MZ, ctype="text/html")
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    n = res.objects[0].notable
    assert any("mismatch" in x for x in n) or "executable served as text" in n


def test_filename_from_content_disposition(tmp_path):
    req = S.request("GET", "/download?id=42", "files.example.com")
    resp = S.response(MZ, ctype="application/octet-stream",
                      disposition='attachment; filename="payroll_2026.exe"')
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    assert res.objects[0].filename == "payroll_2026.exe"


def test_upload_carved(tmp_path):
    body = b"username=admin&password=hunter2&submit=1"
    req = S.request("POST", "/login", "portal.example.com",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=body)
    resp = S.response(b"ok", ctype="text/plain")
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)])
    ups = [o for o in res.objects if o.direction == "upload"]
    assert len(ups) == 1
    assert ups[0].sha256 == hashlib.sha256(body).hexdigest()
    assert "credentials in upload" in ups[0].notable


def test_extract_writes_files(tmp_path):
    req = S.request("GET", "/a.png", "example.com")
    resp = S.response(PNG, ctype="image/png")
    cap = _write(tmp_path, S.convo(req, resp))
    res = analyze([str(cap)], keep_bodies=True)
    out = tmp_path / "objects"
    assert extract(res, str(out)) == 1
    files = list(out.iterdir())
    assert len(files) == 1
    assert hashlib.sha256(files[0].read_bytes()).hexdigest() == \
        hashlib.sha256(PNG).hexdigest()


def test_extract_dedupes_names(tmp_path):
    packets = []
    packets += S.convo(S.request("GET", "/f.bin", "a.com"),
                       S.response(b"AAAA" * 100, ctype="application/octet-stream"),
                       cport=40001)
    packets += S.convo(S.request("GET", "/f.bin", "a.com"),
                       S.response(b"BBBB" * 100, ctype="application/octet-stream"),
                       cport=40002)
    cap = _write(tmp_path, packets)
    res = analyze([str(cap)], keep_bodies=True)
    out = tmp_path / "obj"
    assert extract(res, str(out)) == 2
    assert len(list(out.iterdir())) == 2


def test_pcapng_container(tmp_path):
    req = S.request("GET", "/x.png", "example.com")
    resp = S.response(PNG, ctype="image/png")
    cap = _write(tmp_path, S.convo(req, resp), name="c.pcapng", ng=True)
    res = analyze([str(cap)])
    assert len(res.objects) == 1
    assert res.objects[0].sha256 == hashlib.sha256(PNG).hexdigest()


def test_ipv6_conversation(tmp_path):
    req = S.request("GET", "/v6.png", "example.com")
    resp = S.response(PNG, ctype="image/png")
    cap = _write(tmp_path, S.convo(req, resp, v6=True))
    res = analyze([str(cap)])
    assert len(res.objects) == 1
    assert res.objects[0].sha256 == hashlib.sha256(PNG).hexdigest()


def test_cli_csv_and_json(tmp_path, capsys):
    req = S.request("GET", "/logo.png", "example.com")
    resp = S.response(PNG, ctype="image/png")
    cap = _write(tmp_path, S.convo(req, resp))
    csv_p = tmp_path / "man.csv"
    json_p = tmp_path / "man.json"
    rc = main([str(cap), "--csv", str(csv_p), "--json", str(json_p), "-q"])
    assert rc == 0
    raw = csv_p.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")          # UTF-8 BOM
    assert b"sha256" in raw.splitlines()[0]
    data = _recs(json_p)
    assert data[0]["sha256"] == hashlib.sha256(PNG).hexdigest()


def test_cli_filters(tmp_path):
    packets = []
    packets += S.convo(S.request("GET", "/clean.txt", "a.com"),
                       S.response(b"just text", ctype="text/plain"),
                       cport=40001)
    packets += S.convo(S.request("GET", "/evil.exe", "a.com"),
                       S.response(MZ, ctype="application/octet-stream"),
                       cport=40002)
    cap = _write(tmp_path, packets)
    out = tmp_path / "o.json"
    main([str(cap), "--notable-only", "--json", str(out), "-q"])
    rows = _recs(out)
    assert len(rows) == 1
    assert rows[0]["filename"] == "evil.exe"

    main([str(cap), "--min-severity", "high", "--json", str(out), "-q"])
    assert len(_recs(out)) == 1

    main([str(cap), "--grep", r"\.txt", "--json", str(out), "-q"])
    assert _recs(out)[0]["filename"] == "clean.txt"


def test_csv_injection_guard():
    assert output._san("=cmd()") == "'=cmd()"
    assert output._san("+1") == "'+1"
    assert output._san("-2") == "'-2"
    assert output._san("@x") == "'@x"
    assert output._san("normal.exe") == "normal.exe"


def test_no_http_returns_empty(tmp_path):
    packets = S.convo(b"\x16\x03\x01random tls bytes",
                      b"\x16\x03\x03more tls bytes")
    cap = _write(tmp_path, packets)
    res = analyze([str(cap)])
    assert res.objects == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
