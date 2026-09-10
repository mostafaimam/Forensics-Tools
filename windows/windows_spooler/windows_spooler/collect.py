"""Pair .shd / .spl files under a path and build job rows."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from windows_spooler import flags
from windows_spooler.shd import parse_shd
from windows_spooler.spl import parse_spl


@dataclass
class Result:
    rows: list = field(default_factory=list)
    shd_files: int = 0
    spl_files: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def collect(paths, *, extract_dir=None) -> Result:
    res = Result()
    shds: dict[str, Path] = {}
    spls: dict[str, Path] = {}
    loose: list[Path] = []

    for path in paths:
        p = Path(path)
        files = [p] if p.is_file() else (
            [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else [])
        for f in files:
            ext = f.suffix.lower()
            if ext == ".shd":
                shds[f.stem.lower()] = f
            elif ext == ".spl":
                spls[f.stem.lower()] = f
            elif p.is_file():
                loose.append(f)

    stems = sorted(set(shds) | set(spls))
    for stem in stems:
        shd_p = shds.get(stem)
        spl_p = spls.get(stem)
        job = None
        spl = None
        if shd_p:
            res.shd_files += 1
            res.sources.add(str(shd_p))
            try:
                job = parse_shd(shd_p.read_bytes(), str(shd_p))
            except OSError as e:
                res.errors.append(f"{shd_p}: {e}")
        if spl_p:
            res.spl_files += 1
            res.sources.add(str(spl_p))
            try:
                spl = parse_spl(spl_p.read_bytes(), str(spl_p))
            except OSError as e:
                res.errors.append(f"{spl_p}: {e}")
        if job is None:
            from windows_spooler.shd import ShdJob
            job = ShdJob(source=str(spl_p) if spl_p else stem)
        if spl is None:
            from windows_spooler.spl import SplData
            spl = SplData(source=str(shd_p) if shd_p else stem)

        n, s = flags.classify(job, spl)
        job.notable = n
        row = job.row()
        row.update(spl.row())
        row["source"] = str(shd_p or spl_p)
        row["severity"] = s
        res.rows.append(row)

        if extract_dir and spl_p:
            d = Path(extract_dir)
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{stem}_{spl.fmt.replace('/', '-')}.bin").write_bytes(
                spl_p.read_bytes())

    for f in loose:
        try:
            data = f.read_bytes()
        except OSError as e:
            res.errors.append(f"{f}: {e}")
            continue
        if f.suffix.lower() not in (".shd", ".spl"):
            continue

    res.rows.sort(key=lambda r: (r.get("submit_time") or "",
                                 r.get("job_id") or 0))
    return res
