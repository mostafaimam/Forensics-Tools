"""Load the SUM database set and build access-aggregate rows."""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from windows_sum.esedb import EseDatabase, EseError

_GUID_TABLE = re.compile(
    r"^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$")
_DAYCOL = re.compile(r"^Day(\d{1,3})$", re.I)

# A couple of commonly-cited UAL role GUIDs, used only as a fallback when
# SystemIdentity.mdb (the authoritative RoleGuid -> name map) is absent.
_KNOWN_ROLES = {
    "10A9226F-50EE-49D8-A393-9A501D47CE04": "File Server",
    "7FB09BD3-7FE6-435E-8348-7D8AEFB6CEA3": "Print and Document Services",
}


@dataclass
class Access:
    role_guid: str = ""
    role_name: str = ""
    user: str = ""
    client_name: str = ""
    address: str = ""
    tenant: str = ""
    total_accesses: int = 0
    total_seconds: int = 0
    first_seen: str = ""
    last_seen: str = ""
    insert_date: str = ""
    daily: str = ""
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "last_seen": self.last_seen, "first_seen": self.first_seen,
            "role": self.role_name or self.role_guid, "user": self.user,
            "client_name": self.client_name, "address": self.address,
            "tenant": self.tenant, "total_accesses": self.total_accesses,
            "total_seconds": self.total_seconds, "daily": self.daily,
            "insert_date": self.insert_date, "source": self.source,
            "notable": ";".join(self.notable),
        }


@dataclass
class SumResult:
    rows: list = field(default_factory=list)
    identity: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    dbs: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def _addr(raw, length=None) -> str:
    if not isinstance(raw, (bytes, bytearray)):
        return str(raw or "")
    b = bytes(raw)
    if length and length <= len(b):
        b = b[:length]
    # strip a trailing NUL pad
    for n in (4, 16):
        if len(b) >= n:
            try:
                ip = ipaddress.ip_address(b[:n] if n == 4 else b[:16])
                if not ip.is_unspecified:
                    return str(ip)
            except ValueError:
                pass
    txt = b.split(b"\x00")[0].decode("latin-1", "replace")
    return txt if txt.isprintable() else b.hex()


def _year_of(*iso_strings) -> int | None:
    for s in iso_strings:
        m = re.match(r"(\d{4})-", str(s or ""))
        if m:
            return int(m.group(1))
    return None


def _daily(rec: dict, year: int | None) -> str:
    parts = []
    for k, v in rec.items():
        m = _DAYCOL.match(k)
        if not m or not v:
            continue
        try:
            cnt = int(v)
        except (TypeError, ValueError):
            continue
        if cnt <= 0:
            continue
        dnum = int(m.group(1))
        if year:
            try:
                d = date(year, 1, 1) + timedelta(days=dnum - 1)
                parts.append(f"{d.isoformat()}:{cnt}")
                continue
            except (ValueError, OverflowError):
                pass
        parts.append(f"day{dnum}:{cnt}")
    return ", ".join(parts)


def _load_identity(path: Path, res: SumResult):
    try:
        db = EseDatabase.from_file(str(path))
    except (EseError, OSError) as e:
        res.errors.append(f"{path}: {e}")
        return
    res.sources.add(str(path))
    names = set(db.table_names)
    for cand in ("ROLE_IDS", "RoleIds"):
        if cand in names:
            for rec in db.table(cand).records():
                g = str(rec.get("RoleGuid") or rec.get("Guid") or "").upper()\
                    .strip("{}")
                nm = rec.get("ProductName") or rec.get("RoleName") or \
                    rec.get("Name")
                if g and nm:
                    res.roles[g] = str(nm)
    for cand in ("SYSTEM_IDENTITY", "SystemIdentity"):
        if cand in names:
            for rec in db.table(cand).records():
                res.identity = {k: (v if not isinstance(v, bytes)
                                    else v.hex())
                                for k, v in rec.items() if v is not None}
                break


def _load_roledb(path: Path, res: SumResult):
    try:
        db = EseDatabase.from_file(str(path))
    except (EseError, OSError) as e:
        res.errors.append(f"{path}: {e}")
        return
    res.dbs += 1
    res.sources.add(str(path))
    for tname in db.table_names:
        if not _GUID_TABLE.match(tname):
            continue
        guid = tname.strip("{}").upper()
        role = res.roles.get(guid) or _KNOWN_ROLES.get(guid, "")
        try:
            table = db.table(tname)
        except EseError as e:
            res.errors.append(f"{path}:{tname}: {e}")
            continue
        for rec in table.records():
            first = str(rec.get("FirstSeen") or rec.get("CreationTime") or "")
            last = str(rec.get("LastSeen") or rec.get("LastAccess") or "")
            year = _year_of(last, first)
            a = Access(
                role_guid=guid, role_name=role,
                user=str(rec.get("AuthenticatedUserName")
                         or rec.get("UserName") or "").strip("\x00"),
                client_name=str(rec.get("ClientName") or "").strip("\x00"),
                address=_addr(rec.get("Address"),
                              rec.get("AddressLength")),
                tenant=str(rec.get("TenantId") or "").strip("{}"),
                total_accesses=int(rec.get("TotalAccesses") or 0),
                total_seconds=int(rec.get("TotalActivityDuration")
                                  or rec.get("TotalActivityCount") or 0),
                first_seen=first, last_seen=last,
                insert_date=str(rec.get("InsertDate") or ""),
                daily=_daily(rec, year), source=str(path))
            res.rows.append(a)


def analyze(paths) -> SumResult:
    res = SumResult()
    mdbs: list[Path] = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            mdbs.append(p)
        elif p.is_dir():
            for f in p.rglob("*.mdb"):
                if f.is_file():
                    mdbs.append(f)
    # identity first so role names resolve
    for f in sorted(mdbs, key=lambda x: "identity" not in x.name.lower()):
        if "identity" in f.name.lower():
            _load_identity(f, res)
    for f in mdbs:
        if "identity" in f.name.lower():
            continue
        _load_roledb(f, res)

    res.rows.sort(key=lambda a: (a.last_seen or "", a.role_name, a.user))
    return res
