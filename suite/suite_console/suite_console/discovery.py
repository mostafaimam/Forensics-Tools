"""Discover every tool package in the repository.

Every tool lives at ``<category>/<name>/`` with a ``pyproject.toml``
and a ``<name>/cli.py`` - the same shape for all 142 of them. A new
tool needs no registration here: it is found the moment its directory
matches that shape.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = {"shared", "suite"}


@dataclass
class ToolInfo:
    name: str                 # e.g. "memory_timers"
    category: str             # e.g. "memory"
    description: str
    root: Path                # .../memory/memory_timers
    package_dir: Path         # .../memory/memory_timers/memory_timers
    has_gui: bool
    keywords: list[str] = field(default_factory=list)

    @property
    def display(self) -> str:
        return self.name


def find_repo_root(start: Path | None = None) -> Path:
    here = (start or Path(__file__)).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "shared").is_dir() and (candidate / "windows").is_dir():
            return candidate
    raise RuntimeError(
        "could not locate the Forensics Tools repo root above "
        f"{here} - expected a 'shared' and 'windows' directory nearby")


def discover_tools(root: Path | None = None) -> list[ToolInfo]:
    root = root or find_repo_root()
    tools: list[ToolInfo] = []
    for pp in sorted(root.glob("*/*/pyproject.toml")):
        tool_dir = pp.parent
        category = tool_dir.parent.name
        if category in _SKIP_DIRS:
            continue
        name = tool_dir.name
        package_dir = tool_dir / name
        if not (package_dir / "cli.py").exists():
            continue
        description, keywords = "", []
        try:
            with pp.open("rb") as fh:
                proj = tomllib.load(fh).get("project", {})
            description = proj.get("description", "")
            keywords = list(proj.get("keywords", []))
        except (OSError, tomllib.TOMLDecodeError):
            pass
        tools.append(ToolInfo(
            name=name, category=category, description=description,
            root=tool_dir, package_dir=package_dir,
            has_gui=(package_dir / "gui.py").exists(), keywords=keywords))
    return tools


def categories(tools: list[ToolInfo]) -> list[str]:
    return sorted({t.category for t in tools})
