"""Resolve an ``NSKeyedArchiver`` plist into plain Python data.

Many macOS plists (Dock, saved app state, recent items, Finder sidebar, ...)
are keyed archives: a flat ``$objects`` table plus ``CF$UID`` references.
``plistlib`` returns that structure verbatim; this module walks the graph and
reconstructs ``NSDictionary`` / ``NSArray`` / ``NSString`` / ``NSDate`` / ... .
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

try:
    from plistlib import UID
except ImportError:  # pragma: no cover - very old Python
    UID = None  # type: ignore

_COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

_DICT_CLASSES = {"NSDictionary", "NSMutableDictionary"}
_ARRAY_CLASSES = {"NSArray", "NSMutableArray", "NSSet", "NSMutableSet",
                  "NSOrderedSet"}
_STRING_CLASSES = {"NSString", "NSMutableString"}
_DATA_CLASSES = {"NSData", "NSMutableData"}


def is_keyed_archive(value) -> bool:
    return (isinstance(value, dict) and value.get("$archiver")
            and "$objects" in value and "$top" in value)


class _Resolver:
    def __init__(self, objects: list) -> None:
        self.objects = objects
        self._cache: dict[int, object] = {}
        self._in_progress: set[int] = set()

    def resolve(self, ref):
        if UID is not None and isinstance(ref, UID):
            return self._by_index(ref.data)
        if isinstance(ref, dict) and set(ref) == {"CF$UID"}:
            return self._by_index(ref["CF$UID"])
        return self._plain(ref)

    def _by_index(self, idx: int):
        if idx == 0:
            return None                       # "$null"
        if idx in self._cache:
            return self._cache[idx]
        if idx in self._in_progress:
            return {"$cycle": idx}
        if not (0 <= idx < len(self.objects)):
            return {"$badref": idx}
        self._in_progress.add(idx)
        try:
            out = self._plain(self.objects[idx])
        finally:
            self._in_progress.discard(idx)
        self._cache[idx] = out
        return out

    def _plain(self, obj):
        if obj == "$null":
            return None
        if isinstance(obj, dict):
            if "$class" in obj:
                return self._instance(obj)
            # a bare dict with UID values
            return {k: self.resolve(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.resolve(v) for v in obj]
        return obj

    def _instance(self, obj: dict):
        cls = self.resolve(obj.get("$class"))
        name = ""
        if isinstance(cls, dict):
            name = cls.get("$classname", "")

        if name in _DICT_CLASSES:
            keys = [self.resolve(k) for k in obj.get("NS.keys", [])]
            vals = [self.resolve(v) for v in obj.get("NS.objects", [])]
            return {self._keyify(k): v for k, v in zip(keys, vals)}
        if name in _ARRAY_CLASSES:
            return [self.resolve(v) for v in obj.get("NS.objects", [])]
        if name in _STRING_CLASSES:
            return obj.get("NS.string", "")
        if name in _DATA_CLASSES:
            return obj.get("NS.data", b"")
        if name == "NSDate":
            t = obj.get("NS.time")
            if isinstance(t, (int, float)):
                return (_COCOA_EPOCH + timedelta(seconds=t))
            return t
        if name == "NSUUID":
            b = obj.get("NS.uuidbytes")
            if isinstance(b, (bytes, bytearray)) and len(b) == 16:
                return str(uuid.UUID(bytes=bytes(b)))
            return b
        if name == "NSURL":
            base = self.resolve(obj.get("NS.base"))
            rel = obj.get("NS.relative", "")
            return f"{base}{rel}" if base else rel
        if name == "NSNull":
            return None

        # unknown class: keep everything, resolving references, tag the class
        resolved = {k: self.resolve(v) for k, v in obj.items()
                    if k not in ("$class",)}
        resolved["$class"] = name or "?"
        return resolved

    @staticmethod
    def _keyify(k) -> str:
        return k if isinstance(k, str) else str(k)


def unwrap(archive: dict):
    """Return the resolved ``$top`` of a keyed archive.

    If ``$top`` has a single ``root`` key that value is returned directly;
    otherwise the whole ``$top`` mapping is resolved.
    """
    objects = archive.get("$objects", [])
    r = _Resolver(objects)
    top = archive.get("$top", {})
    resolved_top = {k: r.resolve(v) for k, v in top.items()}
    if list(resolved_top) == ["root"]:
        return resolved_top["root"]
    return resolved_top
