"""Analyse a single file: is it media, and if so what does it carry."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from analysis_gallery import exif as _exif
from analysis_gallery import jpeg, phash, raster, signatures, thumbs, video

# read cap for the in-memory buffer used by parsers (hashing streams anyway)
_BUF_CAP = 128 * 1024 * 1024
# above this pixel count a full stdlib decode is too slow; hash from the
# embedded thumbnail if there is one, otherwise skip the perceptual hash.
# per-format because the pure-Python cost per pixel differs a lot.  The CLI
# --max-decode-mp overrides the default (JPEG-family) ceiling.
_MAX_DECODE_PX = 3_000_000
_DECODE_CAP = {"png": 1_500_000, "gif": 4_000_000, "bmp": 12_000_000}


@dataclass
class MediaFile:
    path: str
    size: int
    kind: str
    category: str
    format: str
    sha256: str = ""
    width: int = 0
    height: int = 0
    megapixels: float = 0.0
    # capture metadata
    make: str = ""
    model: str = ""
    lens: str = ""
    software: str = ""
    serial: str = ""
    orientation: str = ""
    datetime_original: str = ""
    datetime_digitized: str = ""
    datetime_modified: str = ""
    subsecond_offset: str = ""
    exposure: str = ""
    f_number: str = ""
    iso: str = ""
    focal_length: str = ""
    artist: str = ""
    copyright: str = ""
    user_comment: str = ""
    has_maker_note: bool = False
    # gps
    gps_lat: float | None = None
    gps_lon: float | None = None
    gps_altitude: float | None = None
    gps_timestamp: str = ""
    # video
    duration_s: float = 0.0
    # derived
    has_exif: bool = False
    has_thumbnail: bool = False
    phash: str = ""
    phash_group: int = 0
    notes: str = ""
    _grid: tuple | None = field(default=None, repr=False, compare=False)
    _embedded_thumb: bytes = field(default=b"", repr=False, compare=False)

    @property
    def has_gps(self) -> bool:
        return self.gps_lat is not None and self.gps_lon is not None

    @property
    def maps_url(self) -> str:
        if not self.has_gps:
            return ""
        return f"https://www.openstreetmap.org/?mlat={self.gps_lat}&mlon={self.gps_lon}#map=16/{self.gps_lat}/{self.gps_lon}"

    def thumb_datauri(self, box: int = 160) -> str:
        if self._embedded_thumb:
            u = thumbs.jpeg_thumb_datauri(self._embedded_thumb)
            if u:
                return u
        if self._grid:
            g, w, h = self._grid
            return thumbs.gray_thumb_datauri(g, w, h, box)
        return ""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sniff(path: Path) -> str | None:
    """Cheap check: return the media kind from the first bytes, or None."""
    try:
        with path.open("rb") as fh:
            head = fh.read(32)
    except OSError:
        return None
    return signatures.detect(head)


def analyze(path: str | Path, *, want_pixels: bool = False,
            want_thumb: bool = False, hash_files: bool = True,
            max_decode_mp: float | None = None) -> MediaFile | None:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        return None
    try:
        with p.open("rb") as fh:
            head = fh.read(32)
            kind = signatures.detect(head)
            if kind is None:
                return None
            fh.seek(0)
            buf = fh.read(_BUF_CAP)
    except OSError:
        return None

    cat, label = signatures.KINDS.get(kind, ("image", kind.upper()))
    mf = MediaFile(path=str(p), size=size, kind=kind, category=cat,
                   format=label)
    if hash_files:
        mf.sha256 = _sha256(p)

    if cat == "video":
        _fill_video(mf, buf, kind)
    else:
        cap = int(max_decode_mp * 1_000_000) if max_decode_mp else None
        _fill_image(mf, buf, kind, want_pixels or want_thumb, want_thumb, cap)

    if mf.width and mf.height:
        mf.megapixels = round(mf.width * mf.height / 1_000_000, 2)
    if size < 64 or (buf and len(buf) < size and cat == "image"
                     and kind in ("jpeg", "png") and len(buf) < _BUF_CAP):
        pass
    return mf


def _fill_image(mf: MediaFile, buf: bytes, kind: str, want_pixels: bool,
                want_thumb: bool, cap_override: int | None = None) -> None:
    mf.width, mf.height = raster.dimensions(kind, buf)

    ex = None
    if kind == "jpeg":
        tiff = jpeg.embedded_exif(buf)
        if tiff:
            ex = _exif.parse_tiff(tiff)
    elif kind == "tiff":
        ex = _exif.parse_tiff(buf)
    elif kind in ("heif", "webp", "png"):
        # EXIF may still be embedded; try a light scan for a TIFF header
        tiff = _find_tiff(buf)
        if tiff:
            ex = _exif.parse_tiff(tiff)

    if ex is not None:
        mf.has_exif = ex.tags_seen > 0
        mf.make, mf.model, mf.lens = ex.make, ex.model, ex.lens
        mf.software, mf.serial = ex.software, ex.body_serial
        mf.orientation = ex.orientation_text or (
            str(ex.orientation) if ex.orientation else "")
        mf.datetime_original = ex.datetime_original
        mf.datetime_digitized = ex.datetime_digitized
        mf.datetime_modified = ex.datetime_modified
        mf.subsecond_offset = ex.offset_time
        mf.exposure, mf.f_number = ex.exposure_time, ex.f_number
        mf.iso, mf.focal_length = ex.iso, ex.focal_length
        mf.artist, mf.copyright = ex.artist, ex.copyright
        mf.user_comment = ex.user_comment
        mf.has_maker_note = ex.has_maker_note
        mf.gps_lat, mf.gps_lon = ex.gps_lat, ex.gps_lon
        mf.gps_altitude, mf.gps_timestamp = ex.gps_altitude, ex.gps_timestamp
        if ex.thumbnail:
            mf._embedded_thumb = ex.thumbnail
            mf.has_thumbnail = True
        if not mf.width and ex.pixel_x:
            mf.width, mf.height = ex.pixel_x, ex.pixel_y

    if want_pixels:
        grid = None
        # a JPEG's embedded EXIF thumbnail is a free, fast pixel source
        if mf._embedded_thumb:
            grid = jpeg.decode_dc(mf._embedded_thumb)
        if grid is None:
            px = (mf.width or 0) * (mf.height or 0)
            cap = cap_override or _DECODE_CAP.get(kind, _MAX_DECODE_PX)
            if px and px > cap:
                mp = round(px / 1_000_000, 1)
                mf.notes = _join(mf.notes,
                                 f"{mp} MP - not decoded for hashing")
            else:
                grid = raster.gray_grid(kind, buf)
                if grid is None and kind in ("webp", "tiff", "heif"):
                    mf.notes = _join(mf.notes,
                                     "no stdlib decoder for this format")
        if grid:
            mf._grid = grid
            g, w, h = grid
            mf.phash = phash.hex64(phash.dhash(g, w, h))

    if not mf.width:
        mf.notes = _join(mf.notes, "dimensions unknown")


def _fill_video(mf: MediaFile, buf: bytes, kind: str) -> None:
    vi = video.parse(buf, kind)
    mf.width, mf.height = vi.width, vi.height
    mf.duration_s = vi.duration_s
    mf.datetime_original = vi.created
    mf.datetime_modified = vi.modified
    mf.make, mf.model = vi.make, vi.model
    mf.gps_lat, mf.gps_lon = vi.gps_lat, vi.gps_lon
    mf.gps_altitude = vi.gps_altitude
    if vi.created or vi.width:
        mf.has_exif = True
    if kind not in ("mp4", "avi"):
        mf.notes = _join(mf.notes, "container metadata not parsed")


def _find_tiff(buf: bytes) -> bytes:
    for magic in (b"Exif\x00\x00II*\x00", b"Exif\x00\x00MM\x00*"):
        k = buf.find(magic)
        if k >= 0:
            return buf[k + 6:]
    for magic in (b"II*\x00", b"MM\x00*"):
        k = buf.find(magic)
        if 0 <= k < 4096:
            return buf[k:]
    return b""


def _join(a: str, b: str) -> str:
    return f"{a}; {b}" if a else b
