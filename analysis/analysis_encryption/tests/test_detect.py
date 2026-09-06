import io
import os
import struct
import zipfile

from analysis_encryption.detect import analyse


def _w(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_pgp_armored(tmp_path):
    f = analyse(_w(tmp_path, "m.asc",
                   b"-----BEGIN PGP MESSAGE-----\n\nhQ==\n-----END"))
    assert f.verdict == "encrypted" and f.scheme == "pgp"


def test_openssl_salted(tmp_path):
    f = analyse(_w(tmp_path, "s.enc", b"Salted__" + os.urandom(64)))
    assert f.scheme == "openssl" and f.verdict == "encrypted"


def test_luks(tmp_path):
    hdr = b"LUKS\xba\xbe" + struct.pack(">H", 2) + b"\x00" * 2000
    f = analyse(_w(tmp_path, "vol.img", hdr))
    assert f.scheme == "luks" and "LUKS2" in f.detail


def test_bitlocker(tmp_path):
    f = analyse(_w(tmp_path, "disk.bin", b"\xeb\x58\x90-FVE-FS-" + b"\x00" * 512))
    assert f.scheme == "bitlocker" and f.verdict == "encrypted"


def test_keepass(tmp_path):
    f = analyse(_w(tmp_path, "vault.kdbx", b"\x03\xd9\xa2\x9a" + os.urandom(200)))
    assert f.scheme == "keepass"


def test_age(tmp_path):
    f = analyse(_w(tmp_path, "x.age", b"age-encryption.org/v1\n-> X25519 abc"))
    assert f.scheme == "age"


def test_pdf_encrypted(tmp_path):
    body = (b"%PDF-1.6\n1 0 obj<</Type/Catalog>>endobj\n"
            b"trailer<</Root 1 0 R/Encrypt 5 0 R/V 2 /R 3>>\n%%EOF")
    f = analyse(_w(tmp_path, "doc.pdf", body))
    assert f.verdict == "password-protected" and f.scheme == "pdf"
    assert "V=2" in f.detail


def test_pdf_clear(tmp_path):
    f = analyse(_w(tmp_path, "ok.pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<</Root 1 0 R>>"))
    assert f.verdict == "clear"


def _mark_encrypted(zbytes: bytes) -> bytes:
    """Set GP-flag bit 0 on the first local + central header of a zip."""
    b = bytearray(zbytes)
    i = b.find(b"PK\x03\x04")
    b[i + 6] |= 0x01
    j = b.find(b"PK\x01\x02")
    b[j + 8] |= 0x01
    return bytes(b)


def test_zip_encrypted(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("secret.txt", b"x" * 10)
        z.writestr("plain.txt", b"hello")
    f = analyse(_w(tmp_path, "a.zip", _mark_encrypted(buf.getvalue())))
    assert f.verdict == "password-protected" and f.scheme.startswith("zip")
    assert "1/2" in f.detail


def test_zip_clear(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"hello world")
    f = analyse(_w(tmp_path, "b.zip", buf.getvalue()))
    assert f.verdict == "clear"


def test_office_encrypted_cfb(tmp_path):
    blob = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512
            + b"EncryptedPackage" + b"\x00" * 64
            + b"http://schemas.microsoft.com/office/2006/keyEncryptor")
    f = analyse(_w(tmp_path, "doc.docx", blob))
    assert f.verdict == "password-protected" and f.scheme == "office"
    assert "agile" in f.detail


def test_headerless_high_entropy(tmp_path):
    f = analyse(_w(tmp_path, "container.tc", os.urandom(1 << 20)))
    assert f.verdict == "high-entropy"
    assert "veracrypt" in f.scheme
    assert f.entropy > 7.9


def test_compressed_not_flagged(tmp_path):
    import gzip
    f = analyse(_w(tmp_path, "data.gz", gzip.compress(os.urandom(4096))))
    assert f.verdict == "clear"


def test_plain_text_clear(tmp_path):
    f = analyse(_w(tmp_path, "notes.txt", b"just some plain notes\n" * 100))
    assert f.verdict == "clear" and f.entropy < 6
