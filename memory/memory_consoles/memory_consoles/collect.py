"""Tie process discovery and command-shaped string carving together.

The two signals are reported side by side but never correlated with
each other - see the package docstring.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_consoles.carve import carve_command_like
from memory_consoles.loader import MemoryImage, MemoryImageError
from memory_consoles.procscan import scan as scan_procs

COLUMNS = ["kind", "phys_offset", "value", "source"]

_MAX_STRINGS = 5000


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def scan_image(image_path: str, *, carve_strings: bool = True) -> Result:
    res = Result()
    try:
        img = MemoryImage(image_path)
    except (MemoryImageError, OSError) as e:
        res.warnings.append(f"{image_path}: {e}")
        return res

    with img:
        procs = scan_procs(img)
        for p in procs:
            res.rows.append({"kind": "process", "phys_offset":
                            hex(p.phys_offset), "value": p.name,
                            "source": image_path})

        if carve_strings:
            seen: set[str] = set()
            for base, block in img.stream_runs():
                if len(res.rows) - len(procs) >= _MAX_STRINGS:
                    break
                for s in carve_command_like(block):
                    if s in seen:
                        continue
                    seen.add(s)
                    res.rows.append({"kind": "candidate_text",
                                    "phys_offset": hex(base),
                                    "value": s, "source": image_path})

    if not procs:
        res.warnings.append(
            "no conhost.exe/cmd.exe/powershell.exe/pwsh.exe process "
            "found by name")
    return res
