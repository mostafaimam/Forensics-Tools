from _synth import lime_with, u16
from memory_strings.loader import MemoryImage
from memory_strings.patterns import classify
from memory_strings.scan import scan


def _img(tmp_path, placements):
    p = tmp_path / "m.lime"
    p.write_bytes(lime_with(placements))
    return MemoryImage(p)


def test_ascii_and_unicode_addresses(tmp_path):
    img = _img(tmp_path, {
        0x1000: b"\x00hello world this is ascii\x00",
        0x2000: u16("wide unicode string here") + b"\x00\x00",
    })
    hits = list(scan(img, min_len=5))
    a = next(h for h in hits if "ascii" in h.text)
    assert a.phys == 0x1001 and a.encoding == "ascii"
    w = next(h for h in hits if "unicode" in h.text)
    assert w.phys == 0x2000 and w.encoding == "utf-16le"


def test_classified_only(tmp_path):
    img = _img(tmp_path, {
        0x1000: b"\x00just some noise text without iocs\x00",
        0x3000: b"\x00visit http://evil.example/x and mail a@evil.com\x00",
    })
    hits = list(scan(img, min_len=5, classified_only=True))
    cats = {h.category for h in hits}
    assert "url" in cats and "email" in cats
    assert all(h.category for h in hits)


def test_category_filter(tmp_path):
    img = _img(tmp_path, {0x1000: b"\x00ip 10.11.12.13 and host bad.onion here\x00"})
    hits = list(scan(img, min_len=4, categories={"ipv4"}))
    assert [h.match for h in hits] == ["10.11.12.13"]


def test_grep_and_physical_range(tmp_path):
    img = _img(tmp_path, {
        0x1000: b"\x00secret PASSWORD=hunter2 here\x00",
        0x9000: b"\x00another PASSWORD later\x00",
    })
    hits = list(scan(img, min_len=4, grep="password", phys_from=0x2000))
    assert len(hits) == 1 and hits[0].phys >= 0x9000


def test_classify_luhn_rejects_bad_card():
    assert not classify("num 1234567812345670")           # bad luhn
    assert any(c == "credit_card"
               for c, _ in classify("card 4111111111111111"))
