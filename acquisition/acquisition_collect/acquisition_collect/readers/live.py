from __future__ import annotations

import os

from acquisition_collect.paths import IS_WINDOWS, long_path
from acquisition_collect.readers.base import (
    CollectedStream,
    FileTimes,
    Reader,
    ReadError,
)

# Win32 constants for the locked-file fallback.
_GENERIC_READ = 0x80000000
_FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004  # READ | WRITE | DELETE
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_INVALID_HANDLE_VALUE = -1


class LiveReader(Reader):
    """Read files straight from the running filesystem.

    First attempt is a plain ``open()``. On Windows, if that fails with a
    sharing violation / permission error we retry via ``CreateFileW`` with
    ``FILE_SHARE_READ | WRITE | DELETE`` and ``FILE_FLAG_BACKUP_SEMANTICS``,
    which lets us copy files another process holds open (registry hives,
    ``*.evtx``, ``WebCacheV01.dat``, browser history DBs, ...).
    """

    name = "live"

    def __init__(self, **_ignored) -> None:
        pass

    def stat(self, path: str) -> os.stat_result:
        try:
            return os.stat(long_path(path), follow_symlinks=False)
        except OSError as e:
            raise ReadError(f"stat failed: {e}") from e

    def open(self, path: str) -> CollectedStream:
        lp = long_path(path)
        try:
            st = os.stat(lp, follow_symlinks=False)
        except OSError as e:
            raise ReadError(f"stat failed: {e}") from e

        times = FileTimes.from_stat(st)
        try:
            handle = open(lp, "rb", buffering=0)
            return CollectedStream(
                source_path=path, size=st.st_size, times=times,
                handle=handle, backend=self.name,
            )
        except (PermissionError, OSError) as e:
            if not IS_WINDOWS:
                raise ReadError(f"open failed: {e}") from e
            handle = self._open_backup(lp)
            return CollectedStream(
                source_path=path, size=st.st_size, times=times,
                handle=handle, backend=self.name, locked_fallback=True,
            )

    @staticmethod
    def _open_backup(lp: str):
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        invalid = ctypes.c_void_p(-1).value  # INVALID_HANDLE_VALUE, unsigned
        h = kernel32.CreateFileW(
            lp, _GENERIC_READ, _FILE_SHARE_ALL, None, _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_SEQUENTIAL_SCAN, None,
        )
        if not h or h == invalid:
            err = ctypes.get_last_error()
            raise ReadError(
                f"CreateFileW failed (WinError {err}); file is locked and "
                f"needs '--backend vss' and/or an elevated session"
            )
        import msvcrt

        try:
            fd = msvcrt.open_osfhandle(h, os.O_RDONLY)
        except OSError as e:  # pragma: no cover - defensive
            kernel32.CloseHandle(wintypes.HANDLE(h))
            raise ReadError(f"open_osfhandle failed: {e}") from e
        # fd now owns the handle; closing the file object closes the handle.
        return os.fdopen(fd, "rb", buffering=0)
