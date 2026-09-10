"""Heuristic flags for a print job."""

from __future__ import annotations

import re

_SENSITIVE = re.compile(r"\b(password|passwd|confidential|secret|classified|"
                        r"salary|payroll|ssn|social security|bank|invoice|"
                        r"contract|nda|proprietary|restricted|internal only|"
                        r"resign|termination|offer letter|patent)\b", re.I)
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def classify(job, spl) -> tuple[list[str], str]:
    n: list[str] = []
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    n.append("print job recovered from the spool directory")
    bump("low")

    doc = job.document or ""
    if _SENSITIVE.search(doc):
        n.append("document name suggests sensitive content")
        bump("medium")

    if job.machine and job.user:
        m = job.machine.strip("\\").split("\\")[0].lower()
        u = job.user.lower()
        if m and u and m not in u and u not in m and \
                not u.startswith(m[:4]):
            n.append("job owner and source machine name do not correspond")
            bump("low")

    if spl and spl.fmt in ("PostScript",) and spl.bytes_total > 0:
        n.append("PostScript spool data (can carry executable operators)")
        bump("low")

    pages = spl.pages if spl else 0
    if pages >= 100:
        n.append(f"large print job ({pages} pages)")
        bump("medium")

    if spl and spl.parse_error:
        n.append(f"spool data did not parse cleanly: {spl.parse_error}")

    if job.parse_error:
        n.append(f"SHD parse issue: {job.parse_error}")

    return n, sev


def worst(rows) -> str:
    s = "none"
    for r in rows:
        if _ORDER.get(r.get("severity", "none"), 0) > _ORDER[s]:
            s = r["severity"]
    return s
