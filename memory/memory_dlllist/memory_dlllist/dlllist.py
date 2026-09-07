"""Combine the image-VAD scan, process attribution and path heuristics."""

from __future__ import annotations

import ntpath
from dataclasses import dataclass, field

from memory_dlllist import imagevad as _iv
from memory_dlllist import procs as _procs
from memory_dlllist.pagemap import Pml4, find_kernel_dtb

# directories a normal system DLL never loads from
_SUSPECT_DIRS = ("\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\",
                 "\\programdata\\", "\\downloads\\", "\\public\\",
                 "\\perflogs\\", "\\$recycle.bin\\", "\\windows\\tasks\\")
_SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\",
                "\\windows\\winsxs\\", "\\systemroot\\system32\\",
                "\\windows\\assembly\\", "\\windows\\microsoft.net\\")
_KNOWN_SYSTEM_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "rpcrt4.dll", "sechost.dll", "ole32.dll", "combase.dll",
    "shell32.dll", "ws2_32.dll", "crypt32.dll", "wininet.dll",
}


@dataclass
class Module:
    pid: int
    process: str
    base: int
    size: int
    path: str
    name: str
    protection: str
    pool_tag: str
    phys_offset: int
    notable: list[str] = field(default_factory=list)
    confidence: str = "medium"

    def key(self):
        return (self.pid, self.base)


def _flags(path: str, name: str, backed: bool, executable: bool) -> list[str]:
    out: list[str] = []
    low = path.lower()
    if not backed:
        if executable:
            out.append("unbacked-image")
        return out
    if any(d in low for d in _SUSPECT_DIRS):
        out.append("user-writable-path")
    if name in _KNOWN_SYSTEM_DLLS and not any(d in low for d in _SYSTEM_DIRS):
        out.append("system-dll-wrong-path")
    if low.endswith(".dll") and "\\" not in path:
        out.append("no-directory")
    return out


def scan(img, *, progress=None) -> list[Module]:
    procs = _procs.scan(img)
    kdtb = find_kernel_dtb(img)

    def _prog(done, total):
        if progress:
            progress(done, total)

    vads = _iv.scan(img, progress=_prog)

    out: list[Module] = []
    for v in vads:
        owner = None
        for p in procs:
            try:
                if p.pml4.translate(v.start) is not None:
                    owner = p
                    break
            except Exception:  # noqa: BLE001
                continue
        name = ntpath.basename(v.file_path) if v.file_path else ""
        executable = v.protection in ("EXECUTE_READ", "EXECUTE_WRITECOPY",
                                      "EXECUTE_READWRITE", "EXECUTE")
        notable = _flags(v.file_path, name.lower(), v.backed, executable)
        conf = "high" if (owner and v.file_path) else (
            "low" if not v.file_path else "medium")
        if notable:
            conf = "high" if owner else "medium"
        out.append(Module(
            pid=owner.pid if owner else 0,
            process=owner.name if owner else "",
            base=v.start, size=v.size, path=v.file_path, name=name,
            protection=v.protection, pool_tag=v.pool_tag,
            phys_offset=v.phys, notable=notable, confidence=conf))

    best: dict = {}
    for m in out:
        if m.key() not in best:
            best[m.key()] = m
    return sorted(best.values(), key=lambda m: (m.pid or 1 << 30, m.base))
