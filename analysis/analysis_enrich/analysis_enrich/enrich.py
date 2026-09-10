"""Load a timeline, run the enrichers, write it back with extra columns."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

from analysis_enrich import attack as _attack
from analysis_enrich import feeds as _feeds
from analysis_enrich.extract import indicators

_EXTRA_COLS = ["ioc", "ioc_type", "ioc_source", "attack", "attack_name",
               "geo", "known"]


@dataclass
class EnrichResult:
    rows: list = field(default_factory=list)
    columns: list = field(default_factory=list)
    is_jsonl: bool = False
    ioc_hits: int = 0
    attack_hits: int = 0
    known_bad: int = 0
    technique_counts: dict = field(default_factory=dict)


def _load(path: str):
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    if p.suffix.lower() == ".jsonl":
        rows = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
        cols = list(rows[0].keys()) if rows else []
        return rows, cols, True
    if text.lstrip()[:1] in ("[", "{"):
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("rows", [])
        cols = list(rows[0].keys()) if rows else []
        return rows, cols, False
    rdr = csv.DictReader(io.StringIO(text))
    return [dict(r) for r in rdr], list(rdr.fieldnames or []), False


def _row_text(row: dict) -> str:
    return " ".join(str(v) for v in row.values() if v)


def enrich(path: str, *, feed_paths=(), geo_csv=None, known_csv=None,
           attack_on=True) -> EnrichResult:
    rows, cols, is_jsonl = _load(path)
    res = EnrichResult(is_jsonl=is_jsonl)

    feed: dict[str, str] = {}
    for fp in feed_paths:
        feed.update(_feeds.load_feed(fp))
    geo_nets = _feeds.load_geo_csv(geo_csv) if geo_csv else []
    known = _feeds.load_known(known_csv) if known_csv else {}

    for row in rows:
        text = _row_text(row)
        ind = indicators(text)

        ioc_matches = []
        for itype, values in ind.items():
            for v in values:
                if v.lower() in feed:
                    ioc_matches.append((v, itype, feed[v.lower()]))
            # domain of a matched URL / host suffix match
        # host-suffix match for domains
        for d in ind["domain"]:
            for fk, src in feed.items():
                if fk == d or d.endswith("." + fk):
                    ioc_matches.append((d, "domain", src))
        if ioc_matches:
            uniq = sorted(set(ioc_matches))
            row["ioc"] = "; ".join(m[0] for m in uniq)
            row["ioc_type"] = "; ".join(sorted({m[1] for m in uniq}))
            row["ioc_source"] = "; ".join(sorted({m[2] for m in uniq}))
            res.ioc_hits += 1
        else:
            row.setdefault("ioc", "")
            row.setdefault("ioc_type", "")
            row.setdefault("ioc_source", "")

        if attack_on:
            techs = _attack.tag(text)
            if techs:
                row["attack"] = "; ".join(t[0] for t in techs)
                row["attack_name"] = "; ".join(t[1] for t in techs)
                res.attack_hits += 1
                for tid, _ in techs:
                    res.technique_counts[tid] = \
                        res.technique_counts.get(tid, 0) + 1
            else:
                row.setdefault("attack", "")
                row.setdefault("attack_name", "")

        geo_labels = []
        for ip in sorted(ind["ipv4"]):
            g = _feeds.geo_lookup(geo_nets, ip) if geo_nets else ""
            g = g or _feeds.region_for_ip(ip)
            if g and g not in ("private / reserved",):
                geo_labels.append(f"{ip}={g}")
        row["geo"] = "; ".join(geo_labels)

        kk = []
        for h in sorted(ind["md5"] | ind["sha1"] | ind["sha256"]):
            if h in known:
                kk.append(f"{h[:12]}..={known[h]}")
                if known[h] in ("bad", "malicious", "known-bad"):
                    res.known_bad += 1
        row["known"] = "; ".join(kk)

    for c in _EXTRA_COLS:
        if c not in cols:
            cols.append(c)
    res.rows = rows
    res.columns = cols
    return res


def write(res: EnrichResult, path: str):
    p = Path(path)
    if res.is_jsonl or p.suffix.lower() == ".jsonl":
        p.write_text("\n".join(json.dumps(r, default=str)
                               for r in res.rows) + "\n", encoding="utf-8")
        return
    with p.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=res.columns, extrasaction="ignore")
        w.writeheader()
        for r in res.rows:
            w.writerow({k: _san(r.get(k, "")) for k in res.columns})


def _san(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s
