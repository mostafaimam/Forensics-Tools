"""Load CSV / JSON tool outputs and guess which tool produced each."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

# tool -> a set of columns that strongly indicate that tool's output
_SIGNATURES = {
    "windows_evtx": {"event_id", "provider", "channel"},
    "windows_mft": {"si_created", "fn_created"},
    "windows_mft_alt": {"$si_created", "$fn_created"},
    "windows_usn": {"usn", "reason"},
    "windows_logfile": {"lsn", "redo_op"},
    "windows_prefetch": {"run_count", "last_run"},
    "windows_amcache": {"sha1", "first_run"},
    "windows_defender": {"kind", "severity", "notable"},
    "windows_pslogging": {"scriptblock_id", "kind"},
    "windows_registry": {"key_path", "value_name"},
    "windows_srum": {"provider", "bytes_sent"},
}


@dataclass
class Dataset:
    path: str
    tool: str
    rows: list = field(default_factory=list)
    columns: list = field(default_factory=list)


def _load_one(path: Path):
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if text.lstrip()[:1] in ("[", "{"):
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("rows", [data])
        cols = list(rows[0].keys()) if rows and isinstance(rows[0], dict) \
            else []
        return rows, cols
    rdr = csv.DictReader(io.StringIO(text))
    rows = [dict(r) for r in rdr]
    return rows, (rdr.fieldnames or [])


def _guess_tool(path: Path, cols: list[str]) -> str:
    name = path.stem.lower()
    for tool in _SIGNATURES:
        if tool.replace("_alt", "") in name:
            return tool.replace("_alt", "")
    cset = {c.lower() for c in cols}
    best, score = "unknown", 0
    for tool, sig in _SIGNATURES.items():
        s = len(sig & cset)
        if s > score:
            best, score = tool.replace("_alt", ""), s
    return best if score >= 2 else "unknown"


def load(paths) -> list[Dataset]:
    out: list[Dataset] = []
    files: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            files += [f for f in pp.rglob("*")
                      if f.suffix.lower() in (".csv", ".json")]
        elif pp.is_file():
            files.append(pp)
    for f in sorted(set(files)):
        try:
            rows, cols = _load_one(f)
        except (json.JSONDecodeError, OSError, UnicodeError):
            continue
        out.append(Dataset(path=str(f), tool=_guess_tool(f, cols),
                           rows=rows, columns=cols))
    return out
