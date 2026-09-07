"""Container metadata for common video files (no frame decoding).

MP4 / QuickTime (ISO-BMFF) and AVI (RIFF) get real parsing; other
containers return whatever the signature and a light header scan reveal.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# ISO-BMFF epoch is 1904-01-01; offset to Unix epoch in seconds
_MP4_EPOCH_OFFSET = 2082844800


@dataclass
class VideoInfo:
    width: int = 0
    height: int = 0
    duration_s: float = 0.0
    created: str = ""
    modified: str = ""
    gps_lat: float | None = None
    gps_lon: float | None = None
    gps_altitude: float | None = None
    make: str = ""
    model: str = ""
    handler: str = ""
    major_brand: str = ""
    track_count: int = 0

    @property
    def has_gps(self) -> bool:
        return self.gps_lat is not None and self.gps_lon is not None


def _iso8601(secs: int) -> str:
    import datetime as _dt
    try:
        t = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(
            seconds=secs - _MP4_EPOCH_OFFSET)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001
        return ""


def _parse_iso6709(s: str) -> tuple[float | None, float | None, float | None]:
    # e.g. "+37.7749-122.4194+010.500/"
    s = s.strip().rstrip("/")
    nums = []
    cur = ""
    for ch in s:
        if ch in "+-" and cur:
            nums.append(cur)
            cur = ch
        else:
            cur += ch
    if cur:
        nums.append(cur)
    try:
        vals = [float(x) for x in nums if x not in ("", "+", "-")]
    except ValueError:
        return None, None, None
    lat = vals[0] if len(vals) > 0 else None
    lon = vals[1] if len(vals) > 1 else None
    alt = vals[2] if len(vals) > 2 else None
    return lat, lon, alt


def _walk(buf: bytes, start: int, end: int, info: VideoInfo, depth: int = 0):
    i = start
    while i + 8 <= end and depth < 8:
        size = int.from_bytes(buf[i:i + 4], "big")
        typ = buf[i + 4:i + 8]
        header = 8
        if size == 1:
            size = int.from_bytes(buf[i + 8:i + 16], "big")
            header = 16
        elif size == 0:
            size = end - i
        if size < header or i + size > end + 0:
            size = end - i
        body = i + header
        bend = min(end, i + size)

        if typ == b"ftyp":
            info.major_brand = buf[body:body + 4].decode("latin-1", "replace")
        elif typ in (b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta",
                     b"edts"):
            _walk(buf, body, bend, info, depth + 1)
        elif typ == b"meta":
            # meta has a 4-byte version/flags prefix in MP4 (not in QT)
            off = body
            if buf[body + 4:body + 8].isalpha() is False:
                off = body + 4
            _walk(buf, off, bend, info, depth + 1)
        elif typ == b"ilst":
            _walk(buf, body, bend, info, depth + 1)
        elif typ == b"mvhd":
            ver = buf[body]
            if ver == 1:
                ct, mt = struct.unpack(">QQ", buf[body + 4:body + 20])
                ts, dur = struct.unpack(">IQ", buf[body + 20:body + 32])
            else:
                ct, mt, ts, dur = struct.unpack(">IIII", buf[body + 4:body + 20])
            info.created = _iso8601(ct)
            info.modified = _iso8601(mt)
            if ts:
                info.duration_s = round(dur / ts, 3)
        elif typ == b"tkhd":
            ver = buf[body]
            w_off = body + (84 if ver == 1 else 76)
            try:
                w = struct.unpack(">I", buf[w_off:w_off + 4])[0] >> 16
                h = struct.unpack(">I", buf[w_off + 4:w_off + 8])[0] >> 16
                if w and h:
                    info.width = info.width or w
                    info.height = info.height or h
            except Exception:  # noqa: BLE001
                pass
            info.track_count += 1
        elif typ == b"hdlr":
            info.handler = buf[body + 8:body + 12].decode("latin-1", "replace")
        elif typ == b"\xa9xyz" or typ == b"xyz ":
            n = int.from_bytes(buf[body:body + 2], "big")
            txt = buf[body + 4:body + 4 + n].decode("latin-1", "replace")
            lat, lon, alt = _parse_iso6709(txt)
            if lat is not None:
                info.gps_lat, info.gps_lon, info.gps_altitude = lat, lon, alt
        elif typ in (b"\xa9mak", b"\xa9swr", b"\xa9too"):
            info.make = info.make or _read_ilst_text(buf, body, bend)
        elif typ == b"\xa9mod":
            info.model = info.model or _read_ilst_text(buf, body, bend)
        elif typ == b"data":
            pass

        if size <= 0:
            break
        i += size


def _read_ilst_text(buf: bytes, body: int, end: int) -> str:
    # inside an ilst item the text sits in a 'data' box
    j = body
    while j + 8 <= end:
        sz = int.from_bytes(buf[j:j + 4], "big")
        ty = buf[j + 4:j + 8]
        if ty == b"data":
            return buf[j + 16:j + sz].decode("utf-8", "replace").strip()
        if sz <= 0:
            break
        j += sz
    # QuickTime style: 2-byte len + 2-byte lang + text
    n = int.from_bytes(buf[body:body + 2], "big")
    if 0 < n < (end - body):
        return buf[body + 4:body + 4 + n].decode("utf-8", "replace").strip()
    return ""


def _avi(buf: bytes) -> VideoInfo:
    info = VideoInfo(major_brand="AVI")
    idx = buf.find(b"avih")
    if idx > 0 and idx + 48 <= len(buf):
        h0 = idx + 8  # AVIMAINHEADER start
        (us_per_frame,) = struct.unpack("<I", buf[h0:h0 + 4])
        (total_frames,) = struct.unpack("<I", buf[h0 + 16:h0 + 20])
        (w, h) = struct.unpack("<II", buf[h0 + 32:h0 + 40])
        info.width, info.height = w, h
        if us_per_frame and total_frames:
            info.duration_s = round(total_frames * us_per_frame / 1_000_000, 3)
    return info


def parse(buf: bytes, kind: str) -> VideoInfo:
    try:
        if kind == "avi":
            return _avi(buf)
        if kind == "mp4":
            info = VideoInfo()
            _walk(buf, 0, len(buf), info)
            return info
    except Exception:  # noqa: BLE001
        pass
    return VideoInfo()
