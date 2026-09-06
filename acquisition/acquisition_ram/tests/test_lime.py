import io

from acquisition_ram import lime


def test_header_shape():
    h = lime.header(0x1000, 0x1fff)
    assert len(h) == 32
    import struct
    magic, ver, s, e, res = struct.unpack("<IIQQQ", h)
    assert magic == 0x4C694D45 and ver == 1
    assert s == 0x1000 and e == 0x1fff and res == 0


def test_parse_headers_roundtrip():
    buf = io.BytesIO()
    buf.write(lime.header(0x0, 0xfff))
    buf.write(b"A" * 0x1000)
    buf.write(lime.header(0x100000, 0x101fff))
    buf.write(b"B" * 0x2000)
    buf.seek(0)
    ranges = lime.parse_headers(buf)
    assert [(r.start, r.end) for r in ranges] == [(0, 0x1000),
                                                  (0x100000, 0x102000)]
    buf.seek(ranges[1].data_offset)
    assert buf.read(ranges[1].size) == b"B" * 0x2000
