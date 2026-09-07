"""Content-signature detection for image and video containers.

Extension-independent: a ``.jpg`` that is really a PNG, or a photo renamed
to ``.dat``, is classified from its bytes.
"""

from __future__ import annotations

# kind -> ("image" | "video", human label)
KINDS: dict[str, tuple[str, str]] = {
    "jpeg": ("image", "JPEG"),
    "png": ("image", "PNG"),
    "gif": ("image", "GIF"),
    "bmp": ("image", "BMP"),
    "tiff": ("image", "TIFF"),
    "webp": ("image", "WebP"),
    "heif": ("image", "HEIF/HEIC"),
    "jxl": ("image", "JPEG XL"),
    "ico": ("image", "Windows icon"),
    "psd": ("image", "Photoshop"),
    "mp4": ("video", "MP4 / QuickTime"),
    "avi": ("video", "AVI"),
    "matroska": ("video", "Matroska / WebM"),
    "asf": ("video", "ASF / WMV"),
    "flv": ("video", "FLV"),
    "mpeg": ("video", "MPEG program stream"),
    "ogg": ("video", "Ogg"),
}

_FTYP_VIDEO_BRANDS = {
    b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"dash", b"qt  ",
    b"M4V ", b"M4A ", b"m4v ", b"3gp4", b"3gp5", b"3g2a", b"MSNV",
}
_FTYP_HEIF_BRANDS = {b"heic", b"heix", b"hevc", b"heim", b"heis",
                     b"mif1", b"msf1", b"avif", b"avis"}


def detect(head: bytes) -> str | None:
    """Return a kind key from :data:`KINDS`, or ``None``."""
    if len(head) < 12:
        return None

    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:2] == b"BM" and len(head) >= 6:
        return "bmp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head[:4] == b"RIFF":
        fourcc = head[8:12]
        if fourcc == b"WEBP":
            return "webp"
        if fourcc == b"AVI ":
            return "avi"
    if head[:2] == b"\x00\x00" and head[2:4] in (b"\x01\x00", b"\x02\x00"):
        return "ico"
    if head[:4] == b"8BPS":
        return "psd"
    if head[:2] == b"\xff\x0a" or head[:12] == b"\x00\x00\x00\x0cJXL \r\n\x87\n":
        return "jxl"

    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in _FTYP_HEIF_BRANDS:
            return "heif"
        if brand in _FTYP_VIDEO_BRANDS or brand[:3] in (b"3gp", b"mp4"):
            return "mp4"
        # unknown brand but a valid ftyp box: treat as MP4 family
        return "mp4"
    if head[4:12] == b"ftypqt  ":
        return "mp4"

    if head[:4] == b"\x1a\x45\xdf\xa3":
        return "matroska"
    if head[:4] == b"\x30\x26\xb2\x75":
        return "asf"
    if head[:3] == b"FLV":
        return "flv"
    if head[:4] == b"OggS":
        return "ogg"
    if head[:3] == b"\x00\x00\x01" and head[3] in (0xBA, 0xB3):
        return "mpeg"
    return None
