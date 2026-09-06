"""Parse ``at`` / ``batch`` spool jobs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

# spool filename: <queue-letter><5 hex job no><8 hex minutes-since-epoch>
_NAME_RE = re.compile(r"^([a-zA-Z])([0-9a-f]{5})([0-9a-f]{8})$")
_UID_RE = re.compile(r"#\s*atrun\s+uid=(\d+)\s+gid=(\d+)")
_PREAMBLE = re.compile(
    r"^(#!|#\s|umask\b|cd\s|\}\s*$|[A-Za-z_][A-Za-z0-9_]*=.*;\s*export\s|"
    r"export\s|\$\{SHELL)")


@dataclass
class AtJob:
    name: str
    queue: str = ""
    job_no: int = 0
    run_at_utc: str = ""
    uid: str = ""
    command: str = ""
    is_batch: bool = False
    source_file: str = ""


def parse_name(name: str) -> AtJob | None:
    m = _NAME_RE.match(name)
    if not m:
        return None
    q, jobno_hex, when_hex = m.groups()
    minutes = int(when_hex, 16)
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc).timestamp() + minutes * 60
    job = AtJob(name=name, queue=q, job_no=int(jobno_hex, 16))
    job.run_at_utc = datetime.fromtimestamp(dt, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    # a lowercase queue letter is `at`; uppercase is `batch`
    job.is_batch = q.isupper()
    return job


def parse(name: str, text: str) -> AtJob:
    job = parse_name(name) or AtJob(name=name)
    cmd_lines = []
    in_cd_block = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        mu = _UID_RE.search(line)
        if mu:
            job.uid = mu.group(1)
            continue
        if in_cd_block:
            if line.strip() == "}":
                in_cd_block = False
            continue
        if line.lstrip().startswith("cd ") and line.rstrip().endswith("{"):
            in_cd_block = True
            continue
        if _PREAMBLE.match(line):
            continue
        cmd_lines.append(line)
    job.command = "\n".join(cmd_lines).strip()
    return job
