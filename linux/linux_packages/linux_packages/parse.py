"""Per-format parsers for the package-manager logs."""

from __future__ import annotations

import gzip
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Event:
    ts: str = ""                     # ISO-8601 UTC (best effort)
    action: str = ""                 # install | upgrade | remove | reinstall
    package: str = ""                # downgrade | purge | rollback
    version: str = ""
    from_version: str = ""
    arch: str = ""
    source: str = ""                 # dpkg | apt | dnf | yum
    requested_by: str = ""
    command: str = ""
    log_file: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "ts": self.ts, "action": self.action, "package": self.package,
            "version": self.version, "from_version": self.from_version,
            "arch": self.arch, "source": self.source,
            "requested_by": self.requested_by, "command": self.command,
            "log_file": self.log_file, "notable": ";".join(self.notable),
        }


def _read(path: Path) -> str:
    try:
        if path.suffix == ".gz":
            return gzip.decompress(path.read_bytes()).decode(
                "utf-8", "replace")
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# dpkg.log
# --------------------------------------------------------------------------

_DPKG = re.compile(
    r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) (\w[\w-]*) "
    r"(?:([\w.+-]+):?(\w+)? )?(.*)$")
_DPKG_ACTIONS = {"install": "install", "upgrade": "upgrade",
                 "remove": "remove", "purge": "purge",
                 "configure": None, "trigproc": None, "status": None}


def parse_dpkg(path: Path):
    name = path.name
    for line in _read(path).splitlines():
        m = _DPKG.match(line)
        if not m:
            continue
        date, tm, verb, pkg, arch, rest = m.groups()
        act = _DPKG_ACTIONS.get(verb)
        if act is None or not pkg:
            continue
        parts = rest.split()
        from_v, to_v = "", ""
        if verb == "install":
            from_v = parts[0] if parts and parts[0] != "<none>" else ""
            to_v = parts[1] if len(parts) > 1 else (parts[0] if parts else "")
            if from_v:
                act = "reinstall" if from_v == to_v else "upgrade"
        elif verb == "upgrade":
            from_v = parts[0] if parts else ""
            to_v = parts[1] if len(parts) > 1 else ""
        elif verb in ("remove", "purge"):
            from_v = parts[0] if parts and parts[0] != "<none>" else ""
        try:
            ts = _iso(datetime.strptime(f"{date} {tm}", "%Y-%m-%d %H:%M:%S")
                      .replace(tzinfo=timezone.utc))
        except ValueError:
            ts = ""
        yield Event(ts=ts, action=act, package=pkg, version=to_v,
                    from_version=from_v, arch=arch or "", source="dpkg",
                    log_file=name)


# --------------------------------------------------------------------------
# apt history.log
# --------------------------------------------------------------------------

_APT_TS = "%Y-%m-%d  %H:%M:%S"
_APT_PKG = re.compile(r"([\w.+-]+):(\w+) \(([^)]*)\)")


def _apt_ts(s: str) -> str:
    for fmt in ("%Y-%m-%d  %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return _iso(datetime.strptime(s.strip(), fmt)
                        .replace(tzinfo=timezone.utc))
        except ValueError:
            continue
    return ""


def parse_apt_history(path: Path):
    name = path.name
    block: dict[str, str] = {}
    for line in _read(path).splitlines() + [""]:
        if not line.strip():
            if block:
                yield from _apt_block(block, name)
                block = {}
            continue
        if ": " in line:
            k, _, v = line.partition(": ")
            block[k.strip()] = v.strip()


def _apt_block(b: dict, name: str):
    ts = _apt_ts(b.get("Start-Date", ""))
    cmd = b.get("Commandline", "")
    who = b.get("Requested-By", "")
    for field_name, action in (("Install", "install"), ("Upgrade", "upgrade"),
                               ("Remove", "remove"), ("Purge", "purge"),
                               ("Downgrade", "downgrade"),
                               ("Reinstall", "reinstall")):
        raw = b.get(field_name, "")
        if not raw:
            continue
        for m in _APT_PKG.finditer(raw):
            pkg, arch, vers = m.groups()
            # drop the trailing "automatic" / "manual" install-reason marker
            v = [p.strip() for p in vers.split(",")
                 if p.strip() not in ("automatic", "manual")]
            if not v:
                continue
            if action in ("upgrade", "downgrade") and len(v) > 1:
                frm, to = v[0], v[-1]
            else:
                frm, to = "", v[0]
            yield Event(ts=ts, action=action, package=pkg,
                        version=to if action not in ("remove", "purge") else "",
                        from_version=frm or (to if action in ("remove", "purge")
                                             else ""),
                        arch=arch, source="apt", requested_by=who,
                        command=cmd, log_file=name)


# --------------------------------------------------------------------------
# dnf / yum text logs
# --------------------------------------------------------------------------

_YUM = re.compile(
    r"^(\w{3}) (\d\d) (\d\d:\d\d:\d\d) (\d{4})? ?\S* "
    r"(Installed|Erased|Updated|Downgraded|Obsoleted|Reinstalled): "
    r"(\S+)")
_DNF = re.compile(
    r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S* (?:INFO|DDEBUG|SUBDEBUG)? ?"
    r"(Installed|Removed|Upgraded|Downgraded|Reinstalled): (\S+)")
_MON = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec"], 1)}
_ACT_MAP = {"Installed": "install", "Erased": "remove", "Removed": "remove",
            "Updated": "upgrade", "Upgraded": "upgrade",
            "Downgraded": "downgrade", "Reinstalled": "reinstall",
            "Obsoleted": "obsolete"}
_NEVRA = re.compile(r"^(.+)-([^-]+)-([^-]+)\.(\w+)$")


def _split_nevra(s: str):
    s = s.rstrip(".")
    m = _NEVRA.match(s)
    if not m:
        return s, "", ""
    name, ver, rel, arch = m.groups()
    if ":" in ver:
        ver = ver.split(":", 1)[1]
    return name, f"{ver}-{rel}", arch


def parse_yum_dnf(path: Path):
    name = path.name
    src = "dnf" if "dnf" in name else "yum"
    year = datetime.now(timezone.utc).year
    for line in _read(path).splitlines():
        m = _DNF.match(line)
        if m:
            when, verb, nevra = m.groups()
            try:
                ts = _iso(datetime.strptime(when, "%Y-%m-%dT%H:%M:%S")
                          .replace(tzinfo=timezone.utc))
            except ValueError:
                ts = ""
            pkg, ver, arch = _split_nevra(nevra)
            yield Event(ts=ts, action=_ACT_MAP.get(verb, verb.lower()),
                        package=pkg, version=ver, arch=arch, source="dnf",
                        log_file=name)
            continue
        m = _YUM.match(line)
        if m:
            mon, day, tm, yr, verb, nevra = m.groups()
            y = int(yr) if yr else year
            try:
                ts = _iso(datetime(y, _MON.get(mon, 1), int(day),
                                   *(int(x) for x in tm.split(":")),
                                   tzinfo=timezone.utc))
            except ValueError:
                ts = ""
            pkg, ver, arch = _split_nevra(nevra)
            yield Event(ts=ts, action=_ACT_MAP.get(verb, verb.lower()),
                        package=pkg, version=ver, arch=arch, source=src,
                        log_file=name)


# --------------------------------------------------------------------------
# dnf history.sqlite
# --------------------------------------------------------------------------

def parse_dnf_history(path: Path):
    name = path.name
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        con.row_factory = sqlite3.Row
    except sqlite3.Error:
        return
    try:
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "trans" not in tables:
            return
        trans = {r["id"]: dict(r) for r in con.execute(
            "SELECT * FROM trans")}
        # trans_item -> item_id / state ; rpm has the nevra
        state_names = {1: "install", 2: "upgrade", 3: "downgrade",
                       4: "remove", 6: "reinstall", 8: "obsolete"}
        q = ("SELECT ti.trans_id AS tid, ti.action AS action, "
             "r.name AS name, r.version AS version, r.release AS rel, "
             "r.arch AS arch "
             "FROM trans_item ti JOIN rpm r ON r.item_id = ti.item_id")
        try:
            rows = con.execute(q).fetchall()
        except sqlite3.Error:
            rows = []
        for r in rows:
            tr = trans.get(r["tid"], {})
            dt = tr.get("dt_begin") or tr.get("beg_timestamp")
            ts = ""
            if dt:
                try:
                    ts = _iso(datetime.fromtimestamp(int(dt), timezone.utc))
                except (ValueError, OverflowError, OSError):
                    ts = ""
            act = state_names.get(r["action"], str(r["action"]))
            ver = r["version"] or ""
            if r["rel"]:
                ver = f"{ver}-{r['rel']}"
            yield Event(ts=ts, action=act, package=r["name"] or "",
                        version=ver, arch=r["arch"] or "", source="dnf",
                        command=tr.get("cmdline", "") or "",
                        requested_by=str(tr.get("loginuid", "") or ""),
                        log_file=name)
    finally:
        con.close()


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

_KNOWN = {
    "dpkg.log": parse_dpkg,
    "history.log": parse_apt_history,
    "history.sqlite": parse_dnf_history,
}


def read(path: str):
    p = Path(path)
    name = p.name.lower()

    if name.endswith(".sqlite") or name == "history.sqlite":
        yield from parse_dnf_history(p)
        return

    head = ""
    try:
        head = _read(p)[:4000]
    except OSError:
        pass

    if name.startswith("dpkg.log"):
        yield from parse_dpkg(p)
        return
    if name.startswith("history.log") or head.lstrip().startswith("Start-Date:"):
        yield from parse_apt_history(p)
        return
    if "dnf" in name or "yum" in name:
        yield from parse_yum_dnf(p)
        return
    # fall back on content sniffing for a renamed / concatenated log
    if _DPKG.search(head):
        yield from parse_dpkg(p)
        return
    if re.search(r"(Installed|Erased|Removed|Updated|Upgraded): ", head):
        yield from parse_yum_dnf(p)
