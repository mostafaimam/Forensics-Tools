"""Target definitions: what to collect.

Targets are TOML files (parsed with the stdlib ``tomllib`` -> zero third-party
dependencies, which matters for a tool you drop onto an unknown host).

Schema::

    id          = "windows-mft"              # unique slug, required
    name        = "NTFS $MFT"                 # human label, required
    description = "..."                       # optional
    category    = "FileSystem"               # optional, used for --category
    os          = ["windows"]                # windows|linux|macos, required
    needs_raw   = true                        # optional: only collectable via
                                              #   VSS / raw volume access

    [[paths]]
    path      = "%SystemDrive%\\$MFT"         # required; may contain %VARS% and
                                              #   glob wildcards * ? **
    recursive = false                         # optional (default false)
    comment   = "..."                         # optional
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

VALID_OS = {"windows", "linux", "macos"}
BUILTIN_DIR = Path(__file__).parent / "targets"


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class PathSpec:
    path: str
    recursive: bool = False
    comment: str = ""


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    os: frozenset[str]
    paths: tuple[PathSpec, ...]
    description: str = ""
    category: str = "Uncategorised"
    needs_raw: bool = False
    source: str = "<builtin>"

    def applies_to(self, os_name: str) -> bool:
        return os_name in self.os


def _parse(data: dict, source: str) -> Target:
    try:
        tid = str(data["id"]).strip()
        name = str(data["name"]).strip()
        os_list = data["os"]
    except KeyError as e:
        raise TargetError(f"{source}: missing required key {e}")

    if not tid:
        raise TargetError(f"{source}: 'id' must be non-empty")
    if not isinstance(os_list, list) or not os_list:
        raise TargetError(f"{source}: 'os' must be a non-empty array")
    os_set = frozenset(str(o).lower() for o in os_list)
    bad = os_set - VALID_OS
    if bad:
        raise TargetError(f"{source}: unknown os value(s): {sorted(bad)}")

    raw_paths = data.get("paths", [])
    if not isinstance(raw_paths, list) or not raw_paths:
        raise TargetError(f"{source}: at least one [[paths]] entry required")

    specs: list[PathSpec] = []
    for i, p in enumerate(raw_paths):
        if not isinstance(p, dict) or "path" not in p:
            raise TargetError(f"{source}: [[paths]] #{i + 1} needs a 'path' key")
        specs.append(
            PathSpec(
                path=str(p["path"]),
                recursive=bool(p.get("recursive", False)),
                comment=str(p.get("comment", "")),
            )
        )

    return Target(
        id=tid,
        name=name,
        os=os_set,
        paths=tuple(specs),
        description=str(data.get("description", "")),
        category=str(data.get("category", "Uncategorised")),
        needs_raw=bool(data.get("needs_raw", False)),
        source=source,
    )


def load_target_file(path: Path) -> list[Target]:
    """A .toml file may define one target (top-level keys) or many
    (an array of ``[[target]]`` tables)."""
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise TargetError(f"{path}: {e}") from e

    if "target" in data and isinstance(data["target"], list):
        return [
            _parse(entry, f"{path}#{i + 1}")
            for i, entry in enumerate(data["target"])
        ]
    return [_parse(data, str(path))]


@dataclass
class TargetSet:
    targets: list[Target] = field(default_factory=list)

    def _check_unique(self) -> None:
        seen: dict[str, str] = {}
        for t in self.targets:
            if t.id in seen:
                raise TargetError(
                    f"duplicate target id '{t.id}' in {t.source} "
                    f"(first defined in {seen[t.id]})"
                )
            seen[t.id] = t.source

    def for_os(self, os_name: str) -> list[Target]:
        return [t for t in self.targets if t.applies_to(os_name)]

    def select(
        self,
        os_name: str,
        ids: list[str] | None = None,
        categories: list[str] | None = None,
    ) -> list[Target]:
        pool = self.for_os(os_name)
        if not ids and not categories:
            return pool
        id_set = {i.lower() for i in (ids or [])}
        cat_set = {c.lower() for c in (categories or [])}
        chosen = [
            t for t in pool
            if t.id.lower() in id_set or t.category.lower() in cat_set
        ]
        missing = id_set - {t.id.lower() for t in pool}
        if missing:
            raise TargetError(f"unknown target id(s): {sorted(missing)}")
        return chosen


def load_builtin(extra_dirs: list[Path] | None = None) -> TargetSet:
    ts = TargetSet()
    search: list[Path] = [BUILTIN_DIR]
    search.extend(extra_dirs or [])
    for base in search:
        if not base.exists():
            continue
        for f in sorted(base.rglob("*.toml")):
            ts.targets.extend(load_target_file(f))
    ts._check_unique()
    return ts
