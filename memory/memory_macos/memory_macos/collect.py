"""Tie image loading, profile-driven allproc walking, and the
heuristic carve fallback together."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_macos.loader import MemoryImage, MemoryImageError
from memory_macos.pslist import (Profile, ProfileError,
                                 carve_comm_candidates, walk_allproc)

COLUMNS = ["method", "pid", "comm", "proc_va", "source"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def scan_image(image_path: str, *, profile_path: str | None = None) -> \
        Result:
    res = Result()
    try:
        img = MemoryImage(image_path)
    except (MemoryImageError, OSError) as e:
        res.warnings.append(f"{image_path}: {e}")
        return res

    with img:
        if profile_path:
            try:
                profile = Profile.load(profile_path)
                procs = walk_allproc(img, profile)
            except (ProfileError, OSError) as e:
                res.warnings.append(f"profile-driven walk failed: {e}")
                return res
            for pr in procs:
                res.rows.append({"method": "allproc-walk", "pid": pr.pid,
                                "comm": pr.comm, "proc_va":
                                hex(pr.proc_va), "source": image_path})
            if not procs:
                res.warnings.append(
                    "profile loaded but the allproc walk produced no "
                    "entries - check the profile's field offsets")
        else:
            res.warnings.append(
                "no --profile supplied: falling back to heuristic comm "
                "-string carving (low confidence - see the README's "
                "Confidence & Validation section)")
            for s in carve_comm_candidates(img):
                res.rows.append({"method": "heuristic-carve", "pid": "",
                                "comm": s, "proc_va": "", "source":
                                image_path})
    return res
