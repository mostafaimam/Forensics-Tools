"""Acquisition orchestration, hashing and the result model."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

_ALGOS = ("md5", "sha1", "sha256")
_CHUNK = 8 << 20


@dataclass
class Output:
    name: str
    path: str
    size: int = 0
    hashes: dict = field(default_factory=dict)
    note: str = ""
    category: str = ""


@dataclass
class AcquisitionResult:
    method: str                       # linux-kcore | windows-files | macos-files
    host_os: str = ""
    started: str = ""
    finished: str = ""
    seconds: float = 0.0
    outputs: list = field(default_factory=list)     # list[Output]
    ranges: list = field(default_factory=list)      # LiME ranges (linux)
    total_ram: int = 0
    warnings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.outputs) and not any(
            "FAILED" in w for w in self.warnings)


def new_hashers(algos=_ALGOS) -> dict:
    return {a: hashlib.new(a) for a in algos}


def digests(hashers: dict) -> dict:
    return {a: h.hexdigest() for a, h in hashers.items()}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def copy_file(src: Path, dst: Path, *, algos=_ALGOS, progress=None) -> Output:
    hs = new_hashers(algos)
    total = 0
    try:
        with src.open("rb") as fi, dst.open("wb") as fo:
            while True:
                b = fi.read(_CHUNK)
                if not b:
                    break
                fo.write(b)
                for h in hs.values():
                    h.update(b)
                total += len(b)
                if progress:
                    progress(total, src.stat().st_size)
    except (PermissionError, OSError) as e:
        return Output(name=src.name, path=str(dst), size=total,
                      note=f"FAILED: {e}")
    return Output(name=src.name, path=str(dst), size=total, hashes=digests(hs))


def collect_files(sources: list[dict], out_dir: Path, *, algos=_ALGOS,
                  only: set | None = None, progress=None) -> list[Output]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[Output] = []
    for s in sources:
        if only and s["category"] not in only:
            continue
        src = Path(s["path"])
        if s.get("locked"):
            results.append(Output(name=src.name, path="", size=s["size"],
                                  category=s["category"],
                                  note="locked - image the disk or use "
                                       "--source against a mounted copy"))
            continue
        dst = out_dir / (src.name if src.name not in
                         {o.name for o in results} else
                         f"{src.parent.name}_{src.name}")
        o = copy_file(src, dst, algos=algos, progress=progress)
        o.category = s["category"]
        o.note = o.note or s.get("note", "")
        results.append(o)
    return results
