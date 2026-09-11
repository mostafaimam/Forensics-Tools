"""Schema-tolerant extraction of usage records from a parsed document."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

_NAME_KEYS = ("name", "eventName", "event", "probe", "aggregateName",
             "message_type")
_TIME_KEYS = ("timestamp", "time", "startTimestamp", "endTimestamp",
             "collectionTime", "date")
_MSG_KEYS = ("message", "payload", "aggregate", "fields")
_LIST_KEYS = ("aggregates", "records", "items", "events")

_COUNTER_ALIASES = {
    "launches": ("launches", "launchCount", "activations", "count"),
    "foreground_seconds": ("fg_time", "foreground_time", "activeTime",
                           "foregroundSeconds", "fgSeconds"),
    "active_seconds": ("active_time", "activeSeconds", "usageTime"),
    "app": ("appId", "bundleId", "bundle_id", "app", "process"),
}


@dataclass
class Record:
    event_name: str
    app: str
    timestamp: str
    launches: str = ""
    foreground_seconds: str = ""
    active_seconds: str = ""
    extra: dict = field(default_factory=dict)
    source: str = ""

    def row(self) -> dict:
        import json
        return {
            "timestamp": self.timestamp, "event_name": self.event_name,
            "app": self.app, "launches": self.launches,
            "foreground_seconds": self.foreground_seconds,
            "active_seconds": self.active_seconds,
            "extra": json.dumps(self.extra, default=str, sort_keys=True)
            if self.extra else "",
            "source": self.source,
        }


_PLAUSIBLE_LO = datetime(2001, 1, 1, tzinfo=timezone.utc)
_PLAUSIBLE_HI = datetime(2040, 1, 1, tzinfo=timezone.utc)


def _to_iso(v) -> str:
    """Numeric timestamps are ambiguous (Mac-absolute since 2001 vs. Unix
    since 1970, both seen in Apple analytics blobs): try both epochs and
    keep whichever lands in a plausible 2001-2040 window."""
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, (int, float)):
        candidates = []
        for epoch in (_UNIX_EPOCH, _MAC_EPOCH):
            try:
                candidates.append(epoch + timedelta(seconds=v))
            except (OverflowError, OSError, ValueError):
                continue
        plausible = [d for d in candidates if _PLAUSIBLE_LO <= d <=
                    _PLAUSIBLE_HI]
        if plausible:
            return plausible[0].strftime("%Y-%m-%dT%H:%M:%SZ")
        return ""
    return str(v)


def _find(d: dict, keys) -> object:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    low = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in low and low[k.lower()] not in (None, ""):
            return low[k.lower()]
    return None


def _counter(d: dict, canonical: str):
    return _find(d, _COUNTER_ALIASES[canonical])


def _one_record(item: dict, source: str) -> Record | None:
    if not isinstance(item, dict):
        return None
    name = _find(item, _NAME_KEYS)
    ts = _find(item, _TIME_KEYS)
    msg = _find(item, _MSG_KEYS)
    msg = msg if isinstance(msg, dict) else {}
    combined = {**item, **msg}
    app = _counter(combined, "app") or ""
    if not name and not app and not ts:
        return None
    rec = Record(event_name=str(name or ""), app=str(app),
                timestamp=_to_iso(ts), source=source)
    launches = _counter(combined, "launches")
    fg = _counter(combined, "foreground_seconds")
    active = _counter(combined, "active_seconds")
    rec.launches = str(launches) if launches is not None else ""
    rec.foreground_seconds = str(fg) if fg is not None else ""
    rec.active_seconds = str(active) if active is not None else ""
    known = set(_NAME_KEYS) | set(_TIME_KEYS) | set(_MSG_KEYS)
    for alias_set in _COUNTER_ALIASES.values():
        known |= set(alias_set)
    rec.extra = {k: v for k, v in combined.items() if k not in known}
    return rec


def _iter_candidates(doc):
    if isinstance(doc, list):
        for item in doc:
            yield from _iter_candidates(item)
        return
    if isinstance(doc, dict):
        for key in _LIST_KEYS:
            if key in doc and isinstance(doc[key], list):
                for item in doc[key]:
                    yield from _iter_candidates(item)
                return
        yield doc
        return


def extract(doc, source: str) -> list[Record]:
    out = []
    for item in _iter_candidates(doc):
        rec = _one_record(item, source)
        if rec:
            out.append(rec)
    return out
