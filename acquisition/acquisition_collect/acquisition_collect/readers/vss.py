r"""Windows Volume Shadow Copy backend.

Creates a temporary, ``ClientAccessible`` shadow copy per volume on demand
(via CIM / ``Win32_ShadowCopy``), reads the requested files from the snapshot
device (``\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...``), and removes
every snapshot it created on teardown.

Requires an elevated (Administrator) session. If creation fails we raise a
clear error rather than silently falling back, so the examiner knows the
collection is not shadow-consistent.
"""

from __future__ import annotations

import json
import os
import subprocess

from acquisition_collect.paths import IS_WINDOWS
from acquisition_collect.readers.base import CollectedStream, FileTimes, Reader, ReadError

_PS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]


def _run_ps(script: str) -> str:
    try:
        cp = subprocess.run(
            _PS + [script], capture_output=True, text=True, timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ReadError(f"PowerShell invocation failed: {e}") from e
    if cp.returncode != 0:
        raise ReadError(f"PowerShell error: {cp.stderr.strip() or cp.stdout.strip()}")
    return cp.stdout.strip()


class VssReader(Reader):
    name = "vss"

    def __init__(self, **_ignored) -> None:
        if not IS_WINDOWS:
            raise ReadError("the 'vss' backend is only available on Windows")
        # drive letter (upper, no colon) -> GLOBALROOT device path
        self._devices: dict[str, str] = {}
        self._shadow_ids: list[str] = []

    # -- lifecycle ---------------------------------------------------------
    def setup(self) -> None:
        if not _is_admin():
            raise ReadError(
                "the 'vss' backend needs an elevated session "
                "(run the console as Administrator)"
            )

    def teardown(self) -> None:
        for sid in self._shadow_ids:
            try:
                _run_ps(
                    "Get-CimInstance Win32_ShadowCopy | "
                    f"Where-Object ID -eq '{sid}' | Remove-CimInstance"
                )
            except ReadError:
                pass
        self._devices.clear()
        self._shadow_ids.clear()

    # -- snapshot management ---------------------------------------------
    def _device_for(self, drive_letter: str) -> str:
        key = drive_letter.upper()
        if key in self._devices:
            return self._devices[key]
        script = (
            f"$r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create "
            f"-Arguments @{{Volume='{key}:\\'; Context='ClientAccessible'}}; "
            "if ($r.ReturnValue -ne 0) { throw \"Create returned $($r.ReturnValue)\" }; "
            "$s = Get-CimInstance Win32_ShadowCopy | Where-Object ID -eq $r.ShadowID; "
            "$s | Select-Object ID,DeviceObject | ConvertTo-Json -Compress"
        )
        out = _run_ps(script)
        try:
            info = json.loads(out)
        except json.JSONDecodeError as e:
            raise ReadError(f"could not parse shadow-copy info: {out!r}") from e
        device = info["DeviceObject"]
        self._shadow_ids.append(info["ID"])
        # Normalise to an extended-length, openable path root.
        if device.startswith("\\\\?\\"):
            root = device
        elif device.startswith("\\\\"):
            root = "\\\\?\\" + device.lstrip("\\")
        else:
            root = "\\\\?\\GLOBALROOT" + device
        self._devices[key] = root
        return root

    # -- Reader interface ----------------------------------------------
    def resolve(self, path: str) -> str:
        drive, tail = os.path.splitdrive(path)
        if not drive:
            raise ReadError(f"cannot map non-drive path into a shadow copy: {path}")
        device_root = self._device_for(drive.rstrip(":"))
        return device_root.rstrip("\\") + "\\" + tail.lstrip("\\/")

    def stat(self, path: str) -> os.stat_result:
        try:
            return os.stat(self.resolve(path), follow_symlinks=False)
        except OSError as e:
            raise ReadError(f"stat failed in shadow copy: {e}") from e

    def open(self, path: str) -> CollectedStream:
        snap = self.resolve(path)
        try:
            st = os.stat(snap, follow_symlinks=False)
            handle = open(snap, "rb", buffering=0)
        except OSError as e:
            raise ReadError(f"open failed in shadow copy: {e}") from e
        return CollectedStream(
            source_path=path,
            size=st.st_size,
            times=FileTimes.from_stat(st),
            handle=handle,
            backend=self.name,
            extra={"shadow_source": snap},
        )


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - defensive
        return False
