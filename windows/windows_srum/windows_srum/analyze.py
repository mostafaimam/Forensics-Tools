"""Open a SRUDB.dat, resolve the id map, normalise every provider table."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from windows_srum import flags as _flags
from windows_srum import providers as _p
from windows_srum.esedb import EseDatabase, EseError


@dataclass
class Row:
    provider: str
    timestamp: str
    app: str
    user: str
    app_id: int
    user_id: int
    fields: dict
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        d = {"provider": self.provider, "timestamp": self.timestamp,
             "app": self.app, "user": self.user,
             "app_id": self.app_id, "user_id": self.user_id}
        d.update({k: v for k, v in self.fields.items()})
        d["source"] = self.source
        d["notable"] = ";".join(self.notable)
        return d


@dataclass
class Result:
    rows: list = field(default_factory=list)
    providers_seen: dict = field(default_factory=dict)
    id_map_size: int = 0
    errors: list = field(default_factory=list)
    columns: list = field(default_factory=list)


def _sid(blob: bytes) -> str:
    if len(blob) < 8 or blob[0] != 1:
        return blob.hex()
    sub_count = blob[1]
    authority = int.from_bytes(blob[2:8], "big")
    parts = [f"S-1-{authority}"]
    for i in range(sub_count):
        off = 8 + i * 4
        if off + 4 > len(blob):
            break
        parts.append(str(struct.unpack_from("<I", blob, off)[0]))
    return "-".join(parts)


def _decode_idblob(blob, id_type: int) -> str:
    if not isinstance(blob, (bytes, bytearray)):
        return str(blob) if blob is not None else ""
    blob = bytes(blob)
    if id_type == 3:                       # user SID
        return _sid(blob)
    # app id: UTF-16LE string, sometimes prefixed
    txt = blob.decode("utf-16-le", "replace").rstrip("\x00")
    return "".join(c for c in txt if c.isprintable() or c == "\\").strip()


def _load_id_map(db: EseDatabase) -> dict[int, tuple[str, int]]:
    out: dict[int, tuple[str, int]] = {}
    try:
        t = db.table(_p.ID_MAP_TABLE)
    except EseError:
        return out
    for rec in t.records():
        idx = rec.get("IdIndex")
        if idx is None:
            continue
        id_type = rec.get("IdType") or 0
        out[int(idx)] = (_decode_idblob(rec.get("IdBlob"), int(id_type)),
                         int(id_type))
    return out


def analyze(paths) -> Result:
    res = Result()
    seen_cols: list[str] = []
    for path in paths:
        try:
            db = EseDatabase.from_file(path)
        except (EseError, OSError) as e:
            res.errors.append(f"{path}: {e}")
            continue
        if not db.info()["clean"]:
            res.errors.append(f"{path}: database not cleanly shut down "
                              f"(best-effort read)")
        id_map = _load_id_map(db)
        res.id_map_size = len(id_map)

        for name in db.all_table_names():
            guid = name.upper()
            meta = _p.PROVIDERS.get(guid) or _p.PROVIDERS.get(name)
            if meta is None:
                continue
            short, colmap = meta
            try:
                table = db.table(name)
            except EseError as e:
                res.errors.append(f"{name}: {e}")
                continue
            have = {c.name for c in table.columns}
            for rec in table.records():
                ts = rec.get("TimeStamp") or ""
                aid = rec.get("AppId")
                uid = rec.get("UserId")
                app, _ = id_map.get(int(aid), ("", 0)) if aid is not None \
                    else ("", 0)
                user, _ = id_map.get(int(uid), ("", 0)) if uid is not None \
                    else ("", 0)
                fields = {}
                for norm, src in colmap.items():
                    if src in have:
                        fields[norm] = rec.get(src)
                r = Row(provider=short, timestamp=str(ts),
                        app=app or (f"#{aid}" if aid else ""),
                        user=user or (f"#{uid}" if uid else ""),
                        app_id=int(aid) if aid is not None else 0,
                        user_id=int(uid) if uid is not None else 0,
                        fields=fields, source=str(path))
                r.notable = _flags.flag(r)
                res.rows.append(r)
                res.providers_seen[short] = res.providers_seen.get(short, 0) + 1
                for k in ("provider", "timestamp", "app", "user", "app_id",
                          "user_id", *fields.keys(), "source", "notable"):
                    if k not in seen_cols:
                        seen_cols.append(k)

    res.rows.sort(key=lambda r: (r.timestamp or "", r.provider, r.app))
    res.columns = seen_cols
    return res
