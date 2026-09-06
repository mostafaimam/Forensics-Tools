"""Load tool output (CSV / JSON / JSONL) and classify it."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

_ALERT_COLS = ("notable", "flags", "verdict", "status", "alert", "suspicious",
               "timestomped", "deleted")
_ALERT_BAD = {"known-bad", "notable", "encrypted", "password-protected",
              "high-entropy", "yes", "true", "1"}
# tool detection: a column-set signature -> friendly tool name
_SIGNATURES = [
    ({"timestamp_utc", "tool", "description"}, "analysis_timeline"),
    ({"path", "status", "set"}, "analysis_kff"),
    ({"path", "verdict", "scheme"}, "analysis_encryption"),
    ({"pid", "ppid", "name", "create_time"}, "memory_pslist"),
    ({"phys", "encoding", "category"}, "memory_strings"),
    ({"from_addr", "subject", "attachments"}, "analysis_email"),
    ({"schedule", "when", "command"}, "linux_cron"),
    ({"category", "action", "result", "source_ip"}, "linux_syslog"),
    ({"user", "shell", "command"}, "linux_bashhist"),
    ({"si_created", "fn_created"}, "windows_mft"),
    ({"event_id", "provider", "channel"}, "windows_evtx"),
    ({"digest", "group", "representative"}, "analysis_dedupe"),
]


@dataclass
class Source:
    name: str
    path: str
    kind: str                 # csv | json | jsonl
    tool: str
    sha256: str
    columns: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    alert_rows: int = 0

    @property
    def row_count(self) -> int:
        return len(self.rows)


def _detect_tool(columns: set[str]) -> str:
    low = {c.lower() for c in columns}
    for sig, name in _SIGNATURES:
        if sig <= low:
            return name
    return "generic"


def _is_alert(row: dict) -> bool:
    for c in _ALERT_COLS:
        for key in row:
            if key.lower() == c:
                v = str(row[key]).strip().lower()
                if v and v not in ("", "no", "false", "0", "clear", "unknown",
                                   "known-good", "n/a"):
                    return True
    return False


def load(path: str) -> Source:
    p = Path(path)
    raw = p.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    rows: list[dict] = []
    kind = "csv"
    if stripped.startswith("["):
        rows = json.loads(text)
        kind = "json"
    elif stripped.startswith("{"):
        obj = json.loads(text)
        rows = obj.get("rows") or obj.get("files") or obj.get("events") \
            or obj.get("outputs") or [obj]
        kind = "json"
    elif "\n" in stripped and stripped.splitlines()[0].startswith("{"):
        rows = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
        kind = "jsonl"
    else:
        rows = list(csv.DictReader(io.StringIO(text)))
        kind = "csv"

    rows = [r for r in rows if isinstance(r, dict)]
    cols = list(rows[0].keys()) if rows else []
    src = Source(name=p.name, path=str(p), kind=kind, sha256=sha,
                 tool=_detect_tool(set(cols)), columns=cols, rows=rows)
    src.alert_rows = sum(1 for r in rows if _is_alert(r))
    return src
