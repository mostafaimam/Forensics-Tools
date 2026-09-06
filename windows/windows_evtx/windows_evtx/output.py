from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from windows_evtx.evtx.record import EventRecord

CSV_COLUMNS = [
    "RecordNumber", "TimeCreated", "EventId", "Level", "Provider", "Channel",
    "Computer", "UserId", "MapDescription", "ChunkNumber", "Task", "Opcode",
    "Keywords", "ProcessId", "ThreadId", "ActivityId",
    "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
    "PayloadData5", "PayloadData6", "Payload", "SourceFile", "ParseError",
]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _row(r: EventRecord, source: str) -> dict:
    p = r.payload_columns(6)
    return {
        "RecordNumber": r.record_id,
        "TimeCreated": r.time_created_utc or r.timestamp_utc,
        "EventId": r.event_id,
        "Level": r.level,
        "Provider": r.provider,
        "Channel": r.channel,
        "Computer": r.computer,
        "UserId": r.user_id,
        "MapDescription": "",
        "ChunkNumber": r.chunk_number,
        "Task": r.task,
        "Opcode": r.opcode,
        "Keywords": r.keywords,
        "ProcessId": r.process_id,
        "ThreadId": r.thread_id,
        "ActivityId": r.activity_id,
        "PayloadData1": p[0], "PayloadData2": p[1], "PayloadData3": p[2],
        "PayloadData4": p[3], "PayloadData5": p[4], "PayloadData6": p[5],
        "Payload": json.dumps(r.data, ensure_ascii=False),
        "SourceFile": source,
        "ParseError": r.parse_error,
    }


def write_csv(records, path: Path, source: str) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, dialect="excel")
        w.writeheader()
        for r in records:
            w.writerow({k: _san(v) for k, v in _row(r, source).items()})


def _json_obj(r: EventRecord, source: str) -> dict:
    return {
        "record_id": r.record_id,
        "chunk_number": r.chunk_number,
        "written_time_utc": r.timestamp_utc,
        "time_created_utc": r.time_created_utc,
        "event_id": r.event_id,
        "level": r.level,
        "provider": r.provider,
        "channel": r.channel,
        "computer": r.computer,
        "user_id": r.user_id,
        "task": r.task, "opcode": r.opcode, "keywords": r.keywords,
        "process_id": r.process_id, "thread_id": r.thread_id,
        "activity_id": r.activity_id,
        "data": r.data,
        "xml": r.xml,
        "source_file": source,
        "parse_error": r.parse_error,
    }


def write_json(records, path: Path, source: str) -> None:
    path.write_text(
        json.dumps([_json_obj(r, source) for r in records], indent=2,
                   ensure_ascii=False),
        encoding="utf-8")


def write_jsonl(records, path: Path, source: str) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(_json_obj(r, source), ensure_ascii=False,
                                separators=(",", ":")) + "\n")


def write_xml(records, path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        fh.write("<Events>\n")
        for r in records:
            fh.write((r.xml or f"<!-- record {r.record_id}: {r.parse_error} -->")
                     + "\n")
        fh.write("</Events>\n")


def render_table(records, limit: int = 200) -> str:
    out = io.StringIO()
    cols = [("TimeCreated", 27), ("EventId", 8), ("Level", 12),
            ("Provider", 30), ("Computer", 18)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 100 + "\n")
    for r in records[:limit]:
        d = _row(r, "")
        out.write("  ".join(
            (str(d[h])[: w - 1] + "…") if len(str(d[h])) > w
            else str(d[h]).ljust(w) for h, w in cols).rstrip() + "\n")
    if len(records) > limit:
        out.write(f"... {len(records) - limit} more (use --csv)\n")
    return out.getvalue()
