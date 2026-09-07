"""Tie the VAD scan, process attribution and content analysis together."""

from __future__ import annotations

from dataclasses import dataclass

from memory_malfind import analyze as _an
from memory_malfind import procs as _procs
from memory_malfind import vadscan as _vad
from memory_malfind.pagemap import Pml4, find_kernel_dtb


@dataclass
class Detection:
    pid: int
    process: str
    start: int
    end: int
    size: int
    protection: str
    vad_type: str
    pool_tag: str
    verdict: str
    detail: str
    entropy: float
    zeroed: bool
    hexdump: str
    phys_offset: int
    confidence: str

    def key(self):
        return (self.pid, self.start, self.end)


def _confidence(v: _vad.Vad, f: _an.Finding, attributed: bool) -> str:
    if f.verdict == "pe" and attributed:
        return "high"
    if (v.protection & 7) == 6 and f.verdict in ("shellcode", "rwx-data"):
        return "high" if attributed else "medium"
    if f.verdict == "unbacked-exec" and f.zeroed:
        return "low"
    return "medium" if attributed else "low"


def scan(img, *, executable_only: bool = True, want_kernel_dtb: bool = True,
         progress=None) -> list[Detection]:
    procs = _procs.scan(img)
    kdtb = find_kernel_dtb(img) if want_kernel_dtb else None

    def _prog(done, total):
        if progress:
            progress("vad", done, total)

    vads = _vad.scan(img, executable_only=executable_only, progress=_prog)

    out: list[Detection] = []
    for v in vads:
        owner = None
        for p in procs:
            try:
                if p.pml4.translate(v.start) is not None:
                    owner = p
                    break
            except Exception:  # noqa: BLE001
                continue
        pml4 = owner.pml4 if owner else (Pml4(img, kdtb) if kdtb else None)
        head = pml4.read(v.start, 0x400) if pml4 else b""
        f = _an.classify(head, v.start, v.protection_name)
        conf = _confidence(v, f, owner is not None)
        out.append(Detection(
            pid=owner.pid if owner else 0,
            process=owner.name if owner else "",
            start=v.start, end=v.end, size=v.pages << 12,
            protection=v.protection_name, vad_type=v.vad_type,
            pool_tag=v.pool_tag, verdict=f.verdict, detail=f.detail,
            entropy=f.entropy, zeroed=f.zeroed, hexdump=f.hexdump,
            phys_offset=v.phys, confidence=conf))

    best: dict = {}
    for d in out:
        if d.key() not in best or _rank(d) > _rank(best[d.key()]):
            best[d.key()] = d
    return sorted(best.values(),
                  key=lambda d: ({"high": 0, "medium": 1, "low": 2}[d.confidence],
                                 d.pid, d.start))


def _rank(d: Detection) -> int:
    return {"high": 3, "medium": 2, "low": 1}[d.confidence]
