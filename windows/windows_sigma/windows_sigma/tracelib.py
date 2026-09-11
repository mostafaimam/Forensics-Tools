"""tracelib - shared forensic-output helpers for the Forensics Tools suite.

Vendored (copied) into each tool's package, like ``guikit.py``, so every
tool stays zero-dependency and self-contained.  The canonical copy lives
in ``shared/tracelib.py``; ``shared/sync_tracelib.py`` pushes it out to
every tool.

What it gives every tool
------------------------
* **Chain of custody** - a JSON *run manifest* written beside every output
  (or on its own) recording the tool + version, the exact command line,
  the case / examiner / evidence identifiers, start and end time in UTC,
  the host, and **every input file's SHA-256 + size + mtime**.
* **Output integrity** - each output file is SHA-256'd after writing and
  the hash recorded in the manifest.
* **Per-row provenance** - ``evidence_source`` (and optionally
  ``parser_confidence`` / ``tz_provenance``) columns on every CSV row and
  JSON record.
* **Standard warnings** - one ``Warning`` record type for "partial parse",
  "unsupported record", "error", surfaced in the manifest and the
  summary line.
* **Parser confidence** and **timestamp-provenance** vocabularies.
* **Resource limits** - guards against hostile or oversized evidence
  (max input bytes, max records, wall-clock, max output bytes).

Typical use in a tool's ``cli.py``::

    import tracelib
    ...
    p = build_parser()
    tracelib.add_arguments(p)
    a = p.parse_args(argv)
    ctx = tracelib.context(a, "network_dns", __version__)
    ctx.limits.check_paths(a.paths)
    for path in a.paths:
        ctx.add_input(path)
    ...
    res = analyze(...)             # tool appends ctx.warnings as it parses
    tracelib.write_csv(rows, a.csv, COLUMNS, ctx) if a.csv else ...
    tracelib.write_json(rows, a.json, ctx) if a.json else ...
    ctx.finish(outputs=[a.csv, a.json])
    print(ctx.summary_line(len(rows)), file=sys.stderr)
"""

from __future__ import annotations

import csv as _csv
import getpass
import hashlib
import json
import os
import platform
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "CONFIDENCE", "TZ_PROVENANCE", "InputFile", "OutputFile", "Warning",
    "RunContext", "Limits", "LimitExceeded", "add_arguments", "context",
    "hash_file", "hash_bytes", "now_utc", "write_csv", "write_json",
    "write_manifest", "sanitize",
]

SCHEMA = "forensics-tools/run-manifest/1"

# --------------------------------------------------------------------------
# vocabularies
# --------------------------------------------------------------------------

CONFIDENCE = ("high", "medium", "low", "recovered", "heuristic", "unknown")
#   high      - authoritative structure fully parsed
#   medium    - documented structure, some version-dependent fields skipped
#   low       - format is loosely specified / partially reverse-engineered
#   recovered - reconstructed from slack / freelist / a backup copy
#   heuristic - inferred by pattern-matching, not by structure
#   unknown   - confidence not assessed

TZ_PROVENANCE = ("utc-native", "assumed-utc", "local-converted",
                 "offset-applied", "no-timezone", "unknown")
#   utc-native      - the source stores UTC; emitted verbatim
#   assumed-utc     - the source is naive; treated as UTC (may be wrong)
#   local-converted - the source stored local time; converted to UTC
#   offset-applied  - an explicit --tz / recorded offset was applied
#   no-timezone     - the value has no time-of-day / date component
#   unknown         - provenance not assessed


# --------------------------------------------------------------------------
# records
# --------------------------------------------------------------------------

@dataclass
class InputFile:
    path: str
    exists: bool
    size: int = 0
    sha256: str = ""
    modified_utc: str = ""

    def as_dict(self) -> dict:
        return {"path": self.path, "exists": self.exists, "size": self.size,
                "sha256": self.sha256, "modified_utc": self.modified_utc}


@dataclass
class OutputFile:
    path: str
    size: int = 0
    sha256: str = ""

    def as_dict(self) -> dict:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass
class Warning:
    severity: str                    # info | partial | unsupported | error
    code: str                        # short kebab-case slug
    message: str
    location: str = ""               # file / offset / record id

    def as_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code,
                "message": self.message, "location": self.location}


class LimitExceeded(Exception):
    """Raised when evidence exceeds a configured resource limit."""


@dataclass
class Limits:
    max_input_bytes: int = 8 * 1024 ** 3        # 8 GiB per input file
    max_total_input_bytes: int = 64 * 1024 ** 3
    max_records: int = 20_000_000
    max_output_bytes: int = 4 * 1024 ** 3
    wall_seconds: float = 3600.0
    _start: float = field(default_factory=time.monotonic)
    _records: int = 0
    _input_bytes: int = 0

    def check_paths(self, paths) -> None:
        for p in paths or []:
            try:
                sz = Path(p).stat().st_size
            except OSError:
                continue
            if sz > self.max_input_bytes:
                raise LimitExceeded(
                    f"{p}: {sz} bytes exceeds max_input_bytes "
                    f"({self.max_input_bytes})")
            self._input_bytes += sz
        if self._input_bytes > self.max_total_input_bytes:
            raise LimitExceeded(
                f"total input {self._input_bytes} bytes exceeds "
                f"max_total_input_bytes ({self.max_total_input_bytes})")

    def tick(self, n: int = 1) -> None:
        """Call once per emitted record.  Raises on a runaway parse."""
        self._records += n
        if self._records > self.max_records:
            raise LimitExceeded(
                f"record count exceeded max_records ({self.max_records})")
        if (self._records % 4096) == 0 and \
                time.monotonic() - self._start > self.wall_seconds:
            raise LimitExceeded(
                f"wall-clock exceeded {self.wall_seconds}s "
                f"after {self._records} records")

    def check_output(self, nbytes: int) -> None:
        if nbytes > self.max_output_bytes:
            raise LimitExceeded(
                f"output {nbytes} bytes exceeds max_output_bytes "
                f"({self.max_output_bytes})")


# --------------------------------------------------------------------------
# run context
# --------------------------------------------------------------------------

@dataclass
class RunContext:
    tool: str
    version: str
    argv: list = field(default_factory=lambda: list(sys.argv))
    case_id: str = ""
    examiner: str = ""
    evidence_id: str = ""
    notes: str = ""
    enabled: bool = True             # --no-provenance sets this False
    hash_inputs: bool = True
    started_utc: str = field(default_factory=lambda: now_utc())
    finished_utc: str = ""
    host: str = field(default_factory=lambda: _safe(socket.gethostname))
    user: str = field(default_factory=lambda: _safe(getpass.getuser))
    python: str = field(default_factory=lambda: platform.python_version())
    platform: str = field(default_factory=lambda: platform.platform())
    inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)

    # ---- inputs / warnings ------------------------------------------------

    def add_input(self, path) -> InputFile:
        p = Path(path)
        try:
            st = p.stat()
            size = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            exists = True
        except OSError:
            size, mtime, exists = 0, "", False
        sha = ""
        if exists and self.hash_inputs and p.is_file():
            sha = hash_file(str(p))[0]
        rec = InputFile(str(p), exists, size, sha, mtime)
        self.inputs.append(rec)
        return rec

    def warn(self, severity: str, code: str, message: str,
             location: str = "") -> None:
        self.warnings.append(Warning(severity, code, message, location))

    def partial(self, code: str, message: str, location: str = "") -> None:
        self.warn("partial", code, message, location)

    def unsupported(self, code: str, message: str, location: str = "") -> None:
        self.warn("unsupported", code, message, location)

    def error(self, code: str, message: str, location: str = "") -> None:
        self.warn("error", code, message, location)

    def counts(self) -> dict:
        out = {"info": 0, "partial": 0, "unsupported": 0, "error": 0}
        for w in self.warnings:
            out[w.severity] = out.get(w.severity, 0) + 1
        return out

    # ---- outputs / manifest --------------------------------------------

    def note_output(self, path) -> OutputFile:
        sha, size = hash_file(str(path))
        rec = OutputFile(str(path), size, sha)
        self.outputs.append(rec)
        return rec

    def manifest(self) -> dict:
        return {
            "schema": SCHEMA,
            "tool": self.tool,
            "tool_version": self.version,
            "command_line": self.argv,
            "case_id": self.case_id,
            "examiner": self.examiner,
            "evidence_id": self.evidence_id,
            "notes": self.notes,
            "started_utc": self.started_utc,
            "finished_utc": self.finished_utc or now_utc(),
            "environment": {
                "host": self.host, "user": self.user,
                "python": self.python, "platform": self.platform,
            },
            "inputs": [i.as_dict() for i in self.inputs],
            "outputs": [o.as_dict() for o in self.outputs],
            "warnings": [w.as_dict() for w in self.warnings],
            "warning_counts": self.counts(),
        }

    def finish(self, outputs=()) -> str | None:
        """Hash the given output files, then write the run manifest.

        The manifest goes next to the first real output as
        ``<output>.manifest.json``; with no file output it is
        ``<tool>.<started>.manifest.json`` in the working directory.
        Returns the manifest path (or ``None`` if provenance is disabled).
        """
        self.finished_utc = now_utc()
        if not self.enabled:
            return None
        real = [o for o in outputs if o]
        for o in real:
            try:
                self.note_output(o)
            except OSError:
                pass
        if real:
            mpath = str(real[0]) + ".manifest.json"
        elif self.case_id or self.examiner or self.evidence_id:
            # a text-only run, but the examiner asked for provenance
            stamp = self.started_utc.replace(":", "").replace("-", "")
            mpath = f"{self.tool}.{stamp}.manifest.json"
        else:
            return None                       # nothing to accompany
        try:
            Path(mpath).write_text(
                json.dumps(self.manifest(), indent=2), encoding="utf-8")
        except OSError:
            return None
        return mpath

    def summary_line(self, record_count: int) -> str:
        c = self.counts()
        bits = [f"{record_count} record(s)"]
        if c["partial"]:
            bits.append(f"{c['partial']} partial")
        if c["unsupported"]:
            bits.append(f"{c['unsupported']} unsupported")
        if c["error"]:
            bits.append(f"{c['error']} error(s)")
        prov = ""
        if self.case_id or self.evidence_id:
            prov = f"  [case {self.case_id or '-'} / evidence " \
                   f"{self.evidence_id or '-'}]"
        return f"{self.tool}: " + ", ".join(bits) + prov


# --------------------------------------------------------------------------
# argparse integration
# --------------------------------------------------------------------------

def add_arguments(parser) -> None:
    """Add the standard forensic flags to *parser*.

    Values also fall back to the environment: ``TRACELIB_CASE_ID``,
    ``TRACELIB_EXAMINER``, ``TRACELIB_EVIDENCE_ID``.
    """
    g = parser.add_argument_group("forensic provenance")
    g.add_argument("--case-id", default=os.environ.get("TRACELIB_CASE_ID", ""),
                   metavar="ID", help="case / matter identifier (recorded in "
                   "every output's manifest)")
    g.add_argument("--examiner",
                   default=os.environ.get("TRACELIB_EXAMINER", ""),
                   metavar="NAME", help="examiner identifier")
    g.add_argument("--evidence-id",
                   default=os.environ.get("TRACELIB_EVIDENCE_ID", ""),
                   metavar="ID", help="evidence item identifier")
    g.add_argument("--notes", default="", metavar="TEXT",
                   help="free-text note stored in the manifest")
    g.add_argument("--no-provenance", action="store_true",
                   help="do not write a run manifest or provenance columns")
    g.add_argument("--no-hash-inputs", action="store_true",
                   help="skip SHA-256 of input files (faster, less complete)")
    g.add_argument("--max-input-bytes", type=int, default=0, metavar="N",
                   help="refuse an input file larger than N bytes")
    g.add_argument("--max-records", type=int, default=0, metavar="N",
                   help="stop after N emitted records")
    g.add_argument("--wall-seconds", type=float, default=0.0, metavar="S",
                   help="abort a run that exceeds S seconds")


def context(args, tool: str, version: str) -> RunContext:
    lim = Limits()
    if getattr(args, "max_input_bytes", 0):
        lim.max_input_bytes = args.max_input_bytes
    if getattr(args, "max_records", 0):
        lim.max_records = args.max_records
    if getattr(args, "wall_seconds", 0.0):
        lim.wall_seconds = args.wall_seconds
    return RunContext(
        tool=tool, version=version, argv=list(sys.argv),
        case_id=getattr(args, "case_id", "") or "",
        examiner=getattr(args, "examiner", "") or "",
        evidence_id=getattr(args, "evidence_id", "") or "",
        notes=getattr(args, "notes", "") or "",
        enabled=not getattr(args, "no_provenance", False),
        hash_inputs=not getattr(args, "no_hash_inputs", False),
        limits=lim)


# --------------------------------------------------------------------------
# hashing / time helpers
# --------------------------------------------------------------------------

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_file(path, *, chunk: int = 1 << 20) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as fh:
            while block := fh.read(chunk):
                h.update(block)
                size += len(block)
    except OSError:
        return "", 0
    return h.hexdigest(), size


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe(fn) -> str:
    try:
        return str(fn())
    except Exception:  # noqa: BLE001
        return ""


def sanitize(v) -> str:
    """CSV formula-injection guard (kept here so tools share one copy)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


# --------------------------------------------------------------------------
# writers
# --------------------------------------------------------------------------

_PROVENANCE_COLS = ("evidence_source", "parser_confidence", "tz_provenance")


def _row_provenance(r: dict, ctx: RunContext, confidence: str = "",
                    tz: str = "") -> dict:
    """Fill the provenance columns on a row if the tool did not."""
    out = dict(r)
    if not out.get("evidence_source"):
        out["evidence_source"] = (r.get("source_db") or r.get("entry_file")
                                  or r.get("source_file") or r.get("source")
                                  or r.get("exporter") or r.get("fmt") or "")
    if not out.get("parser_confidence"):
        out["parser_confidence"] = confidence
    if not out.get("tz_provenance"):
        out["tz_provenance"] = tz
    if ctx is not None and ctx.enabled:
        out.setdefault("case_id", ctx.case_id)
        out.setdefault("evidence_id", ctx.evidence_id)
    return out


def write_csv(rows, path, columns, ctx: RunContext | None = None, *,
              provenance_columns: bool = True, confidence: str = "",
              tz: str = "") -> None:
    cols = list(columns)
    if provenance_columns and (ctx is None or ctx.enabled):
        for c in _PROVENANCE_COLS:
            if c not in cols:
                cols.append(c)
        if ctx is not None and (ctx.case_id or ctx.evidence_id):
            for c in ("case_id", "evidence_id"):
                if c not in cols:
                    cols.append(c)
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            rr = _row_provenance(r, ctx, confidence, tz)
            w.writerow({k: sanitize(rr.get(k, "")) for k in cols})


def write_json(rows, path, ctx: RunContext | None = None, *,
               key: str = "records", confidence: str = "", tz: str = "",
               envelope: bool = False) -> None:
    """Write *rows* as JSON.

    By default a bare list is written (so existing consumers are
    unaffected) and the run manifest is a ``<path>.manifest.json``
    sidecar written by :meth:`RunContext.finish`.  Pass ``envelope=True``
    to instead wrap the document as ``{"manifest": ..., "records": ...}``.
    Either way, each record gains the provenance fields.
    """
    recs = list(rows)
    if ctx is not None and ctx.enabled:
        recs = [_row_provenance(r, ctx, confidence, tz) for r in recs]
        if envelope:
            Path(path).write_text(
                json.dumps({"manifest": ctx.manifest(), key: recs}, indent=2),
                encoding="utf-8")
            return
    Path(path).write_text(json.dumps(recs, indent=2), encoding="utf-8")


def write_manifest(ctx: RunContext, path) -> None:
    Path(path).write_text(json.dumps(ctx.manifest(), indent=2),
                          encoding="utf-8")
