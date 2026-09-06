from _synth import sqlite_db, tiny_bmp, tiny_gif, tiny_jpeg, tiny_png, zip_blob
from trace_recover import validators as V


def test_png_exact_length():
    data = tiny_png(8, 8)
    assert V.v_png(memoryview(data + b"TRAILINGJUNK")) == len(data)


def test_bmp_exact_length():
    data = tiny_bmp()
    assert V.v_bmp(memoryview(data + b"\x00" * 50)) == len(data)


def test_sqlite_exact_length():
    data = sqlite_db()
    assert V.v_sqlite(memoryview(data + b"junkjunkjunk")) == len(data)


def test_gif_length():
    data = tiny_gif()
    assert V.v_gif(memoryview(data + b"\xff" * 20)) == len(data)


def test_jpeg_length():
    data = tiny_jpeg()
    assert V.v_jpeg(memoryview(data + b"\x00" * 10)) == len(data)


def test_zip_length():
    data = zip_blob()
    assert V.v_zip(memoryview(data + b"AFTER")) == len(data)


def test_validators_reject_garbage():
    g = memoryview(b"not a real file at all, just text" * 10)
    assert V.v_png(g) is None
    assert V.v_bmp(g) is None
    assert V.v_sqlite(g) is None
    assert V.v_zip(g) is None


def test_gzip_roundtrip():
    import gzip
    raw = b"the quick brown fox " * 100
    gz = gzip.compress(raw)
    assert V.v_gzip(memoryview(gz + b"trailing")) == len(gz)
