"""Open an acquisition source: a file, a volume, or a whole physical disk."""

from __future__ import annotations

import os
import sys
from pathlib import Path


class SourceError(Exception):
    pass


class Source:
    """A read-only, size-known byte source with bad-region tolerance."""

    def __init__(self, path: str, sector_size: int = 512):
        self.path = path
        self.sector_size = sector_size
        self._fh = self._open(path)
        self.size = self._determine_size()
        self.bad_ranges: list[tuple[int, int]] = []

    # -- platform open -------------------------------------------------
    @staticmethod
    def _open(path: str):
        try:
            if os.name == "nt" and path.startswith("\\\\.\\"):
                return open(path, "rb", buffering=0)
            return open(path, "rb")
        except OSError as e:
            raise SourceError(f"cannot open {path}: {e}") from None

    def _determine_size(self) -> int:
        # regular file
        try:
            st = os.fstat(self._fh.fileno())
            if st.st_size > 0:
                return st.st_size
        except OSError:
            pass
        # Linux block device
        if self.path.startswith("/dev/"):
            name = os.path.basename(self.path)
            for cand in (f"/sys/block/{name}/size",
                         f"/sys/class/block/{name}/size"):
                try:
                    return int(Path(cand).read_text()) * 512
                except (OSError, ValueError):
                    pass
        # Windows physical drive via IOCTL
        if os.name == "nt" and self.path.startswith("\\\\.\\"):
            n = _win_disk_length(self._fh.fileno())
            if n:
                return n
        # last resort: seek to end
        try:
            cur = self._fh.tell()
            self._fh.seek(0, os.SEEK_END)
            n = self._fh.tell()
            self._fh.seek(cur)
            if n > 0:
                return n
        except OSError:
            pass
        raise SourceError(f"could not determine the size of {self.path}")

    # -- reading -----------------------------------------------------
    def read(self, offset: int, length: int, *, retries: int = 2) -> bytes:
        """Read *length* bytes; on I/O error, retry then zero-fill and log."""
        try:
            self._fh.seek(offset)
            data = self._fh.read(length)
            if len(data) < length and offset + length <= self.size:
                data += b"\x00" * (length - len(data))
            return data
        except OSError:
            pass
        # narrow down: read sector by sector
        out = bytearray()
        ss = self.sector_size
        pos = offset
        end = offset + length
        while pos < end:
            n = min(ss, end - pos)
            chunk = None
            for _ in range(retries + 1):
                try:
                    self._fh.seek(pos)
                    chunk = self._fh.read(n)
                    break
                except OSError:
                    chunk = None
            if chunk is None or len(chunk) < n:
                out += b"\x00" * n
                self._note_bad(pos, n)
            else:
                out += chunk
            pos += n
        return bytes(out)

    def _note_bad(self, offset: int, length: int) -> None:
        if self.bad_ranges and self.bad_ranges[-1][0] + \
                self.bad_ranges[-1][1] == offset:
            s, ln = self.bad_ranges[-1]
            self.bad_ranges[-1] = (s, ln + length)
        else:
            self.bad_ranges.append((offset, length))

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _win_disk_length(fileno: int) -> int:
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
    except Exception:  # noqa: BLE001
        return 0
    IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
    try:
        handle = msvcrt.get_osfhandle(fileno)
        out = ctypes.c_ulonglong(0)
        returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            wintypes.HANDLE(handle), IOCTL_DISK_GET_LENGTH_INFO, None, 0,
            ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(returned), None)
        return int(out.value) if ok else 0
    except Exception:  # noqa: BLE001
        return 0


def probe(path: str) -> dict:
    """Quick describe of a source without a full open where possible."""
    info = {"path": path, "kind": "file"}
    if path.startswith("\\\\.\\"):
        info["kind"] = "windows-device"
    elif path.startswith("/dev/"):
        info["kind"] = "block-device"
    try:
        with Source(path) as s:
            info["size"] = s.size
    except SourceError as e:
        info["error"] = str(e)
    return info
