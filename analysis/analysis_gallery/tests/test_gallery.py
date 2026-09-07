import csv
import json

import pytest

from analysis_gallery import exif, gif, jpeg, phash, png, raster, signatures
from analysis_gallery import bmp, video
from analysis_gallery.cli import main
from analysis_gallery.media import analyze
from analysis_gallery.scan import scan

import _synth as s


# --------------------------------------------------------------------------
# signatures
# --------------------------------------------------------------------------

def test_signature_detection():
    assert signatures.detect(s.gray_png(4, 4)[:32]) == "png"
    assert signatures.detect(s.bmp24(4, 4)[:32]) == "bmp"
    assert signatures.detect(s.gif_solid(4, 4)[:32]) == "gif"
    assert signatures.detect(s.flat_jpeg()[:32]) == "jpeg"
    assert signatures.detect(s.mp4()[:32]) == "mp4"
    assert signatures.detect(b"II*\x00\x08\x00\x00\x00" + b"\x00" * 8) == "tiff"
    assert signatures.detect(b"not media at all, really") is None


def test_extension_independence(tmp_path):
    p = tmp_path / "invoice.pdf"          # lies about being a PDF
    p.write_bytes(s.gray_png(20, 20))
    mf = analyze(p)
    assert mf is not None and mf.kind == "png"


# --------------------------------------------------------------------------
# EXIF / GPS
# --------------------------------------------------------------------------

def test_exif_core_fields():
    blk = s.exif_block(make="Canon", model="EOS R5", software="fw 1.9",
                       datetime_original="2026:08:15 14:30:00",
                       orientation=6, lens="RF 50mm F1.2")
    ex = exif.parse_tiff(blk)
    assert ex.make == "Canon"
    assert ex.model == "EOS R5"
    assert ex.software == "fw 1.9"
    assert ex.lens == "RF 50mm F1.2"
    assert ex.datetime_original == "2026:08:15 14:30:00"
    assert ex.orientation == 6
    assert ex.orientation_text == "rotate-90-cw"
    assert ex.iso == "ISO 400"
    assert ex.f_number == "f/2.8"
    assert ex.pixel_x == 64 and ex.pixel_y == 48


def test_exif_gps_decimal():
    blk = s.exif_block(gps=(37.7749, -122.4194))
    ex = exif.parse_tiff(blk)
    assert ex.has_gps
    assert ex.gps_lat == pytest.approx(37.7749, abs=1e-3)
    assert ex.gps_lon == pytest.approx(-122.4194, abs=1e-3)
    assert ex.gps_altitude == pytest.approx(10.5, abs=0.1)
    assert ex.gps_timestamp.endswith("Z")


def test_exif_big_endian():
    blk = s.exif_block(make="Nikon", model="Z8", bo=">")
    ex = exif.parse_tiff(blk)
    assert ex.make == "Nikon" and ex.model == "Z8"


def test_exif_embedded_thumbnail():
    thumb = s.flat_jpeg(180, 2, 2)
    blk = s.exif_block(thumbnail=thumb)
    ex = exif.parse_tiff(blk)
    assert ex.thumbnail[:2] == b"\xff\xd8"
    assert len(ex.thumbnail) == len(thumb)


def test_exif_garbage_is_safe():
    assert exif.parse_tiff(b"").tags_seen == 0
    assert exif.parse_tiff(b"II*\x00\xff\xff\xff\xff").tags_seen == 0


# --------------------------------------------------------------------------
# decoders + dimensions
# --------------------------------------------------------------------------

def test_png_decode_and_dims():
    buf = s.rgb_png(50, 30, text={"Comment": "shot"})
    assert raster.dimensions("png", buf) == (50, 30)
    grid, w, h = png.decode_gray(buf)
    assert (w, h) == (50, 30) and len(grid) == 1500
    assert png.info(buf).text["Comment"] == "shot"


def test_png_palette_and_interlace_paths():
    # sub-byte greyscale
    buf = s.gray_png(16, 16, lambda x, y: (x * 16) % 256)
    grid, w, h = png.decode_gray(buf)
    assert grid[0] < grid[15]


def test_bmp_decode():
    buf = s.bmp24(24, 18, lambda x, y: (255, 255, 255) if x < 12 else (0, 0, 0))
    assert bmp.info(buf).width == 24
    grid, w, h = bmp.decode_gray(buf)
    assert grid[0] > 200 and grid[w - 1] < 50


def test_gif_dims_comment_and_decode():
    buf = s.gif_solid(40, 24, color_index=2, comment="carved")
    g = gif.info(buf)
    assert (g.width, g.height) == (40, 24)
    assert g.comment == "carved"
    grid, w, h = gif.decode_gray(buf)
    assert (w, h) == (40, 24)
    assert len(set(grid)) == 1               # solid colour


def test_jpeg_info_and_dc_decode():
    buf = s.pattern_jpeg(12, 9, seed=3)
    j = jpeg.info(buf)
    assert (j.width, j.height) == (96, 72)
    out = jpeg.decode_dc(buf)
    assert out is not None
    grid, gw, gh = out
    assert (gw, gh) == (12, 9)
    # block (0,0) value = (0 + 0 + 3*91) % 240 + 8 = 273%240+8 = 41
    assert grid[0] == pytest.approx(41, abs=2)


def test_jpeg_embedded_exif_roundtrip():
    blk = s.exif_block(make="Sony", model="A7 IV", gps=(48.8584, 2.2945))
    buf = s.gradient_jpeg(8, 8, exif=blk)
    tiff = jpeg.embedded_exif(buf)
    ex = exif.parse_tiff(tiff)
    assert ex.make == "Sony"
    assert ex.gps_lat == pytest.approx(48.8584, abs=1e-3)


# --------------------------------------------------------------------------
# perceptual hash
# --------------------------------------------------------------------------

def test_dhash_stable_under_resize():
    big = s.rgb_png(200, 160, lambda x, y: (x, (x + y) % 256, y))
    small = s.rgb_png(100, 80, lambda x, y: (x * 2, (x * 2 + y * 2) % 256,
                                             y * 2))
    gb = png.decode_gray(big)
    gs = png.decode_gray(small)
    hb = phash.dhash(gb[0], gb[1], gb[2])
    hs = phash.dhash(gs[0], gs[1], gs[2])
    assert phash.hamming(hb, hs) <= 6


def test_group_puts_lookalikes_together():
    hashes = [0b0101, 0b0101, 0b0111, 0xFFFF, None]
    gids = phash.group(hashes, threshold=1)
    assert gids[0] == gids[1] == gids[2] != 0
    assert gids[3] == 0 and gids[4] == 0


# --------------------------------------------------------------------------
# video
# --------------------------------------------------------------------------

def test_mp4_metadata_and_gps():
    buf = s.mp4(1280, 720, 9.25, created_iso6709="+37.5090-122.2620/",
                creation_unix=1_600_000_000)
    vi = video.parse(buf, "mp4")
    assert (vi.width, vi.height) == (1280, 720)
    assert vi.duration_s == pytest.approx(9.25, abs=0.01)
    assert vi.created.startswith("2020-09-13T")
    assert vi.gps_lat == pytest.approx(37.5090, abs=1e-3)
    assert vi.gps_lon == pytest.approx(-122.2620, abs=1e-3)


def test_avi_dimensions():
    import struct
    # AVIMAINHEADER: usPerFrame, maxBytes, padding, flags, totalFrames,
    #   initialFrames, streams, suggestedBuffer, width, height, ...
    hdr = struct.pack("<8I", 40000, 0, 0, 0, 300, 0, 1, 0)
    avih = b"avih" + struct.pack("<I", 56) + hdr + struct.pack("<II", 640, 480)
    buf = b"RIFF" + struct.pack("<I", 200) + b"AVI " + b"LIST....hdrl" + avih
    vi = video.parse(buf, "avi")
    assert (vi.width, vi.height) == (640, 480)
    assert vi.duration_s == pytest.approx(12.0, abs=0.1)


# --------------------------------------------------------------------------
# scan + CLI integration
# --------------------------------------------------------------------------

def _tree(tmp_path):
    d = tmp_path / "case"
    (d / "sub").mkdir(parents=True)
    blk = s.exif_block(make="Canon", model="EOS R5", gps=(51.5074, -0.1278),
                       datetime_original="2026:07:01 09:00:00")
    (d / "IMG_0001.jpg").write_bytes(s.pattern_jpeg(10, 10, seed=1, exif=blk))
    (d / "IMG_0001_copy.jpg").write_bytes(
        s.pattern_jpeg(10, 10, seed=1, exif=blk))          # look-alike
    (d / "IMG_0002.jpg").write_bytes(s.pattern_jpeg(10, 10, seed=9))
    (d / "screenshot.png").write_bytes(s.rgb_png(120, 80))
    (d / "sub" / "clip.mp4").write_bytes(
        s.mp4(1920, 1080, 5.0, created_iso6709="+40.0-74.0/"))
    (d / "readme.txt").write_bytes(b"not a picture")
    (d / "sub" / "diagram.bmp").write_bytes(s.bmp24(30, 30))
    return d


def test_scan_finds_media_and_skips_the_rest(tmp_path):
    d = _tree(tmp_path)
    res = scan([str(d)], phash_on=True)
    assert res.scanned == 6
    assert res.images == 5 and res.videos == 1
    assert res.with_gps == 3          # 2 geotagged jpegs + 1 mp4
    assert res.skipped == 1


def test_scan_groups_lookalikes(tmp_path):
    d = _tree(tmp_path)
    res = scan([str(d)], phash_on=True, threshold=4)
    groups = {f.phash_group for f in res.files if f.phash_group}
    assert groups
    a = next(f for f in res.files if f.path.endswith("IMG_0001.jpg"))
    b = next(f for f in res.files if f.path.endswith("IMG_0001_copy.jpg"))
    assert a.phash_group == b.phash_group != 0


def test_cli_csv_json_and_exit(tmp_path):
    d = _tree(tmp_path)
    out = tmp_path / "g.csv"
    js = tmp_path / "g.json"
    rc = main(["scan", str(d), "--phash", "--csv", str(out), "--json",
               str(js), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 6
    geo = [r for r in rows if r["gps_lat"]]
    assert len(geo) == 3
    data = json.loads(js.read_text())
    assert any(r["make"] == "Canon" for r in data)


def test_cli_gps_only_filter(tmp_path):
    d = _tree(tmp_path)
    out = tmp_path / "geo.csv"
    main(["scan", str(d), "--gps-only", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["gps_lat"] for r in rows)


def test_cli_html_contact_sheet(tmp_path):
    d = _tree(tmp_path)
    out = tmp_path / "gallery.html"
    main(["scan", str(d), "--phash", "--html", str(out), "-q"])
    text = out.read_text(encoding="utf-8")
    assert "<figure class=\"card\"" in text
    assert "data:image/" in text            # at least one thumbnail embedded
    assert "openstreetmap.org" in text      # a GPS link
    assert "Look-alike group" in text


def test_cli_category_filter(tmp_path):
    d = _tree(tmp_path)
    out = tmp_path / "v.csv"
    main(["scan", str(d), "--category", "video", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 1 and rows[0]["category"] == "video"


def test_cli_missing_path():
    assert main(["scan", "/no/such/place"]) == 2


def test_csv_injection_guard(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    blk = s.exif_block(make="=cmd()", model="ok")
    (d / "a.jpg").write_bytes(s.flat_jpeg(120, 4, 3, exif=blk))
    out = tmp_path / "o.csv"
    main(["scan", str(d), "--csv", str(out), "-q"])
    raw = out.read_text(encoding="utf-8-sig")
    assert "'=cmd()" in raw
