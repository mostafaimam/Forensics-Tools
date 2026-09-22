"""Tie image loading, profile-driven list walking, and the heuristic
carve fallback together."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_linux.loader import MemoryImage, MemoryImageError
from memory_linux.pslist import (Profile, ProfileError,
                                 carve_comm_candidates, walk_task_list)

COLUMNS = ["method", "pid", "comm", "task_struct_va", "source"]


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
                tasks = walk_task_list(img, profile)
            except (ProfileError, OSError) as e:
                res.warnings.append(f"profile-driven walk failed: {e}")
                return res
            for t in tasks:
                res.rows.append({"method": "task-list-walk", "pid": t.pid,
                                "comm": t.comm, "task_struct_va":
                                hex(t.task_struct_va), "source":
                                image_path})
            if not tasks:
                res.warnings.append(
                    "profile loaded but the task list walk produced no "
                    "entries - check the profile's field offsets")
        else:
            res.warnings.append(
                "no --profile supplied: falling back to heuristic comm "
                "-string carving (low confidence - see the README's "
                "Confidence & Validation section)")
            for s in carve_comm_candidates(img):
                res.rows.append({"method": "heuristic-carve", "pid": "",
                                "comm": s, "task_struct_va": "",
                                "source": image_path})
    return res
