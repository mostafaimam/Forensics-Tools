"""Run every engine collector under a root and flag the results."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from linux_containers import engines as _eng
from linux_containers import flags as _flags


@dataclass
class Result:
    containers: list = field(default_factory=list)
    engines: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def analyze(paths) -> Result:
    res = Result()
    for path in paths:
        root = Path(path)
        for fn in (_eng.docker, _eng.podman, _eng.containerd):
            try:
                found = fn(root)
            except (OSError, ValueError) as e:
                res.errors.append(f"{fn.__name__}: {e}")
                continue
            for c in found:
                c.notable = _flags.flag(c)
                res.containers.append(c)
                res.engines[c.engine] = res.engines.get(c.engine, 0) + 1
                if c.source:
                    res.sources.append(c.source)

    res.containers.sort(key=lambda c: (c.engine, c.created or "", c.name))
    return res
