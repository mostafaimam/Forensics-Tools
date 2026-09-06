"""Test helpers - build a small 'disk' with bad-sector simulation."""

from __future__ import annotations

import hashlib


def disk_bytes(n_sectors: int = 4096, sector: int = 512) -> bytes:
    out = bytearray()
    for s in range(n_sectors):
        out += bytes(((s * 31 + i) % 256 for i in range(sector)))
    return bytes(out)


def md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


class FlakySource:
    """Stands in for acquisition_image.source.Source with some unreadable sectors."""

    def __init__(self, data: bytes, bad_sectors=(3, 4, 10), sector_size=512):
        self._data = data
        self.size = len(data)
        self.sector_size = sector_size
        self._bad = set(bad_sectors)
        self.bad_ranges: list[tuple[int, int]] = []

    def read(self, offset: int, length: int, *, retries: int = 2) -> bytes:
        out = bytearray()
        ss = self.sector_size
        pos = offset
        end = offset + length
        while pos < end:
            n = min(ss, end - pos)
            sec = pos // ss
            if sec in self._bad:
                out += b"\x00" * n
                if self.bad_ranges and \
                        self.bad_ranges[-1][0] + self.bad_ranges[-1][1] == pos:
                    s, ln = self.bad_ranges[-1]
                    self.bad_ranges[-1] = (s, ln + n)
                else:
                    self.bad_ranges.append((pos, n))
            else:
                out += self._data[pos:pos + n]
            pos += n
        return bytes(out)

    def close(self):
        pass
