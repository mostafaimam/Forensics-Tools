"""Turn heterogeneous input rows into normalised :class:`Event` objects.

Known ``trace-*`` outputs are recognised from their column names and each
timestamp column is exploded into its own event (so a Prefetch row with eight
run times yields eight execution events).  Anything unrecognised is handled by
the generic adapter, driven by ``--time-field`` / ``--message-field``.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Iterator

from analysis_timeline.model import Event
from analysis_timeline.timeparse import TimeParseError, to_utc


class AdapterConfig:
    def __init__(self, time_fields=None, message_fields=None, host=None,
                 allow_epoch=False):
        self.time_fields = list(time_fields or [])
        self.message_fields = list(message_fields or [])
        self.host = host
        self.allow_epoch = allow_epoch


# (timestamp column, event type) pairs per recognised layout
_TRACE_COLLECT = {
    "created_utc": "created", "modified_utc": "modified",
    "accessed_utc": "accessed", "changed_utc": "changed",
    "collected_utc": "collected",
}
_TRACE_RECYCLE = {"deleted_utc": "deleted"}
_TRACE_PREFETCH = {f"run_time_{i}_utc": "execution" for i in range(1, 9)}
_TRACE_PREFETCH["volume_created_utc"] = "volume-created"


def _warn(warnings, msg):
    if msg not in warnings:
        warnings.append(msg)


def _emit(row_no, source, ts_raw, ttype, *, tool, artifact, description,
          host, user, extra, warnings, cfg):
    if not ts_raw:
        return None
    try:
        ts = to_utc(ts_raw, allow_epoch=cfg.allow_epoch)
    except TimeParseError as e:
        _warn(warnings, f"{source}: {e}")
        return None
    return Event(
        timestamp=ts, timestamp_type=ttype, tool=tool, artifact=artifact,
        description=description, host=host or cfg.host or "", user=user,
        source_file=source, source_row=row_no, extra=extra,
    )


def _rows_from_csv(text: str):
    reader = csv.DictReader(io.StringIO(text))
    return reader.fieldnames or [], list(reader)


def _iter_csv(path: Path, cfg: AdapterConfig, warnings: list) -> Iterator[Event]:
    text = path.read_text(encoding="utf-8-sig")
    header, rows = _rows_from_csv(text)
    hset = set(header)
    source = str(path)

    layout = None
    if {"created_utc", "modified_utc", "source_path"} <= hset:
        layout = ("trace-collect", "filesystem", _TRACE_COLLECT, "source_path")
    elif "deleted_utc" in hset and "original_path" in hset:
        layout = ("trace-recycle", "recycle-bin", _TRACE_RECYCLE, "original_path")
    elif "run_time_1_utc" in hset and "executable" in hset:
        layout = ("trace-prefetch", "program-execution", _TRACE_PREFETCH, "executable")

    for i, row in enumerate(rows, 1):
        if layout:
            tool, artifact, tsmap, descfield = layout
            host = row.get("host", "") or _host_from_row(row)
            user = row.get("sid", "") or row.get("user", "")
            base = row.get(descfield, "")
            for col, ttype in tsmap.items():
                if col not in row or not row[col]:
                    continue
                desc = _describe(tool, ttype, base, row)
                extra = {k: v for k, v in row.items()
                         if v and k not in tsmap and k != descfield}
                ev = _emit(i, source, row[col], ttype, tool=tool,
                           artifact=artifact, description=desc, host=host,
                           user=user, extra=extra, warnings=warnings, cfg=cfg)
                if ev:
                    yield ev
        else:
            yield from _generic_row(source, i, row, cfg, warnings, header)


def _host_from_row(row: dict) -> str:
    src = row.get("source", "") or row.get("source_file", "")
    # trace-* run folders look like  trace-collect_<HOST>_<UTCSTAMP>
    for part in str(src).replace("\\", "/").split("/"):
        if part.startswith("trace-") and part.count("_") >= 2:
            return part.split("_")[1]
    return ""


def _describe(tool, ttype, base, row) -> str:
    if tool == "trace-prefetch":
        n = row.get("referenced_files", "")
        if ttype == "execution":
            return f"{base} executed" + (f" ({n} files referenced)" if n else "")
        return f"{base} volume created"
    if tool == "trace-recycle":
        sid = row.get("sid", "")
        return f"deleted to Recycle Bin: {base}" + (f" [sid {sid}]" if sid else "")
    if tool == "trace-collect":
        return f"{ttype} timestamp: {base}"
    return base or f"{tool} {ttype}"


def _generic_row(source, i, row, cfg, warnings, header):
    tfields = cfg.time_fields or [h for h in header
                                  if "time" in h.lower() or "date" in h.lower()
                                  or h.lower() in ("timestamp", "ts", "@timestamp")]
    if not tfields:
        _warn(warnings, f"{source}: no timestamp column; use --time-field")
        return
    mfields = cfg.message_fields or [h for h in header
                                     if h.lower() in ("message", "description",
                                                      "msg", "event", "details")]
    desc = " | ".join(str(row[m]) for m in mfields if row.get(m)) or \
        " | ".join(f"{k}={v}" for k, v in row.items() if v)[:500]
    for tf in tfields:
        if row.get(tf):
            ev = _emit(i, source, row[tf], tf, tool="generic-csv",
                       artifact=Path(source).stem, description=desc,
                       host="", user="", extra=dict(row), warnings=warnings,
                       cfg=cfg)
            if ev:
                yield ev


def _iter_json(path: Path, cfg: AdapterConfig, warnings: list) -> Iterator[Event]:
    source = str(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        records = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    _warn(warnings, f"{source}: bad JSONL line ({e})")
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            _warn(warnings, f"{source}: {e}")
            return
        records = data if isinstance(data, list) else [data]

    for i, rec in enumerate(records, 1):
        if not isinstance(rec, dict):
            continue
        flat = {k: ("" if v is None else v if isinstance(v, (str, int, float))
                    else json.dumps(v, default=str))
                for k, v in rec.items()}
        # prefetch JSON: run_times_utc is a list
        if "run_times_utc" in rec and isinstance(rec["run_times_utc"], list):
            exe = rec.get("executable", "")
            n = len(rec.get("referenced_files", []) or [])
            for t in rec["run_times_utc"]:
                ev = _emit(i, source, t, "execution", tool="trace-prefetch",
                           artifact="program-execution",
                           description=f"{exe} executed ({n} files referenced)",
                           host="", user="", extra={"source": rec.get("source", "")},
                           warnings=warnings, cfg=cfg)
                if ev:
                    yield ev
            continue
        yield from _generic_row(source, i, flat, cfg, warnings, list(flat))


def iter_events(path: Path, cfg: AdapterConfig, warnings: list) -> Iterator[Event]:
    suffix = path.suffix.lower()
    if suffix in (".json", ".jsonl"):
        yield from _iter_json(path, cfg, warnings)
    else:
        yield from _iter_csv(path, cfg, warnings)
